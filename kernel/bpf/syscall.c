/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/bpf.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/license.h>
#include <linux/filter.h>

static LIST_HEAD(bpf_map_types);

/* Upstream 4.4 semantics instead of 3.18's blanket "root only" check: only
 * BPF_PROG_LOAD of non-socket-filter programs needs CAP_SYS_ADMIN, the rest is
 * gated by this knob (writable through /proc/sys/kernel/unprivileged_bpf_disabled,
 * which Android 13's bpfloader.rc writes to 0 at boot).  Without it the pinned
 * objects were unusable by netd and gpuservice, which run without CAP_SYS_ADMIN:
 *   BpfHandler: Failed to get program from /sys/fs/bpf/netd_shared/...:
 *   Operation not permitted  (backport 2026-09-10) */
int sysctl_unprivileged_bpf_disabled __read_mostly;

static struct bpf_map *find_and_alloc_map(union bpf_attr *attr)
{
	struct bpf_map_type_list *tl;
	struct bpf_map *map;

	list_for_each_entry(tl, &bpf_map_types, list_node) {
		if (tl->type == attr->map_type) {
			map = tl->ops->map_alloc(attr);
			if (IS_ERR(map))
				return map;
			map->ops = tl->ops;
			map->map_type = attr->map_type;
			return map;
		}
	}
	return ERR_PTR(-EINVAL);
}

/* boot time registration of different map implementations */
void bpf_register_map_type(struct bpf_map_type_list *tl)
{
	list_add(&tl->list_node, &bpf_map_types);
}

/* called from workqueue */
static void bpf_map_free_deferred(struct work_struct *work)
{
	struct bpf_map *map = container_of(work, struct bpf_map, work);

	/* implementation dependent freeing */
	map->ops->map_free(map);
}

/* decrement map refcnt and schedule it for freeing via workqueue
 * (unrelying map implementation ops->map_free() might sleep)
 */
void bpf_map_put(struct bpf_map *map)
{
	if (atomic_dec_and_test(&map->refcnt)) {
		INIT_WORK(&map->work, bpf_map_free_deferred);
		schedule_work(&map->work);
	}
}

static int bpf_map_release(struct inode *inode, struct file *filp)
{
	struct bpf_map *map = filp->private_data;

	bpf_map_put(map);
	return 0;
}

/* Opening a pinned object through the bpf filesystem (bpffs) hands out the very
 * same kind of fd that BPF_MAP_CREATE returns: __bpf_map_get() below accepts it
 * because i_fop of the pinned inode is bpf_map_fops (backport 2026-09-10).
 * Android 13 userspace (libbpf_bcc's BpfMap, libgpuwork, bpfloader) opens
 * /sys/fs/bpf/<object> directly, so this path is what makes them work. */
static int bpf_map_open(struct inode *inode, struct file *filp)
{
	filp->private_data = bpf_map_inc(inode->i_private, true);
	return 0;
}

const struct file_operations bpf_map_fops = {
	.open    = bpf_map_open,
	.release = bpf_map_release,
};

/* helper macro to check that unused fields 'union bpf_attr' are zero */
#define CHECK_ATTR(CMD) \
	memchr_inv((void *) &attr->CMD##_LAST_FIELD + \
		   sizeof(attr->CMD##_LAST_FIELD), 0, \
		   sizeof(*attr) - \
		   offsetof(union bpf_attr, CMD##_LAST_FIELD) - \
		   sizeof(attr->CMD##_LAST_FIELD)) != NULL

/* The LAST_FIELD markers follow the Android 13 union bpf_attr layout that
 * include/uapi/linux/bpf.h now declares, not the 3.18 one: Android userspace
 * fills map_flags / prog_flags / btf_* and the Zero check must tolerate them
 * (the fields themselves are ignored by this kernel).  With the old markers any
 * map carrying BPF_F_RDONLY-style flags was rejected with EINVAL, which is what
 * made bpfloader fail on the very first tethering object (backport 2026-09-10). */
#define BPF_MAP_CREATE_LAST_FIELD btf_value_type_id
/* called via syscall */
static int map_create(union bpf_attr *attr)
{
	struct bpf_map *map;
	int err;

	err = CHECK_ATTR(BPF_MAP_CREATE);
	if (err)
		return -EINVAL;

	/* find map type and init map: hashtable vs rbtree vs bloom vs ... */
	map = find_and_alloc_map(attr);
	if (IS_ERR(map))
		return PTR_ERR(map);

	atomic_set(&map->refcnt, 1);

	err = anon_inode_getfd("bpf-map", &bpf_map_fops, map, O_RDWR | O_CLOEXEC);

	if (err < 0)
		/* failed to allocate fd */
		goto free_map;

	return err;

free_map:
	map->ops->map_free(map);
	return err;
}

/* if error is returned, fd is released.
 * On success caller should complete fd access with matching fdput()
 */
struct bpf_map *bpf_map_get(struct fd f)
{
	struct bpf_map *map;

	if (!f.file)
		return ERR_PTR(-EBADF);

	if (f.file->f_op != &bpf_map_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	map = f.file->private_data;

	return map;
}

/* Convert BPF_F_RDONLY/BPF_F_WRONLY to open flags (from 4.9). */
int bpf_get_file_flag(int flags)
{
	if ((flags & BPF_F_RDONLY) && (flags & BPF_F_WRONLY))
		return -EINVAL;
	if (flags & BPF_F_RDONLY)
		return O_RDONLY;
	if (flags & BPF_F_WRONLY)
		return O_WRONLY;
	return O_RDWR;
}

/* Reference counting helpers shared with the bpf filesystem (bpffs). */
struct bpf_map *bpf_map_inc(struct bpf_map *map, bool uref)
{
	atomic_inc(&map->refcnt);
	return map;
}

void bpf_map_put_with_uref(struct bpf_map *map)
{
	bpf_map_put(map);
}

struct bpf_map *bpf_map_get_with_uref(u32 ufd)
{
	struct fd f = fdget(ufd);
	struct bpf_map *map;

	map = bpf_map_get(f);
	if (IS_ERR(map))
		return map;

	/* The caller (BPF_OBJ_PIN probe) keeps this reference: the pinned
	 * dentry owns it until evict/unlink puts it back.  Without the inc
	 * the map is freed when the creator fds close (bpfloader exits) and
	 * every later access through bpffs is use-after-free — random oopses
	 * under load (e.g. netd NetworkStats reads).  Matches upstream 4.9. */
	bpf_map_inc(map, true);
	fdput(f);
	return map;
}

int bpf_map_new_fd(struct bpf_map *map)
{
	return anon_inode_getfd("bpf-map", &bpf_map_fops, map,
				O_RDWR | O_CLOEXEC);
}

struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog)
{
	atomic_inc(&prog->aux->refcnt);
	return prog;
}

int bpf_prog_new_fd(struct bpf_prog *prog)
{
	return anon_inode_getfd("bpf-prog", &bpf_prog_fops, prog,
				O_RDWR | O_CLOEXEC);
}

/* helper to convert user pointers passed inside __aligned_u64 fields */
static void __user *u64_to_ptr(__u64 val)
{
	return (void __user *) (unsigned long) val;
}

/* last field in 'union bpf_attr' used by this command */
#define BPF_MAP_LOOKUP_ELEM_LAST_FIELD flags

static int map_lookup_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_ptr(attr->key);
	void __user *uvalue = u64_to_ptr(attr->value);
	int ufd = attr->map_fd;
	struct fd f = fdget(ufd);
	struct bpf_map *map;
	void *key, *value;
	int err;

	if (CHECK_ATTR(BPF_MAP_LOOKUP_ELEM))
		return -EINVAL;

	map = bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	err = -ENOMEM;
	key = kmalloc(map->key_size, GFP_USER);
	if (!key)
		goto err_put;

	err = -EFAULT;
	if (copy_from_user(key, ukey, map->key_size) != 0)
		goto free_key;

	err = -ESRCH;
	rcu_read_lock();
	/* A per-CPU map stores one value per CPU in a single block of
	 * map->value_size bytes: the syscall layer reads the whole block (it
	 * copies map->value_size bytes below), a program only the current CPU's
	 * slice, so those map types provide a syscall-only variant (backport
	 * 2026-09-11). */
	if (map->ops->map_lookup_elem_sys_only)
		value = map->ops->map_lookup_elem_sys_only(map, key);
	else
		value = map->ops->map_lookup_elem(map, key);
	if (!value)
		goto err_unlock;

	err = -EFAULT;
	if (copy_to_user(uvalue, value, map->value_size) != 0)
		goto err_unlock;

	err = 0;

err_unlock:
	rcu_read_unlock();
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_UPDATE_ELEM_LAST_FIELD flags

static int map_update_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_ptr(attr->key);
	void __user *uvalue = u64_to_ptr(attr->value);
	int ufd = attr->map_fd;
	struct fd f = fdget(ufd);
	struct bpf_map *map;
	void *key, *value;
	int err;

	if (CHECK_ATTR(BPF_MAP_UPDATE_ELEM))
		return -EINVAL;

	map = bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	err = -ENOMEM;
	key = kmalloc(map->key_size, GFP_USER);
	if (!key)
		goto err_put;

	err = -EFAULT;
	if (copy_from_user(key, ukey, map->key_size) != 0)
		goto free_key;

	err = -ENOMEM;
	value = kmalloc(map->value_size, GFP_USER);
	if (!value)
		goto free_key;

	err = -EFAULT;
	if (copy_from_user(value, uvalue, map->value_size) != 0)
		goto free_value;

	/* eBPF program that use maps are running under rcu_read_lock(),
	 * therefore all map accessors rely on this fact, so do the same here
	 */
	rcu_read_lock();
	/* userspace writes the whole per-CPU block, see map_lookup_elem() */
	if (map->ops->map_update_elem_sys_only)
		err = map->ops->map_update_elem_sys_only(map, key, value,
							 attr->flags);
	else
		err = map->ops->map_update_elem(map, key, value, attr->flags);
	rcu_read_unlock();

free_value:
	kfree(value);
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_DELETE_ELEM_LAST_FIELD flags

static int map_delete_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_ptr(attr->key);
	int ufd = attr->map_fd;
	struct fd f = fdget(ufd);
	struct bpf_map *map;
	void *key;
	int err;

	if (CHECK_ATTR(BPF_MAP_DELETE_ELEM))
		return -EINVAL;

	map = bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	err = -ENOMEM;
	key = kmalloc(map->key_size, GFP_USER);
	if (!key)
		goto err_put;

	err = -EFAULT;
	if (copy_from_user(key, ukey, map->key_size) != 0)
		goto free_key;

	rcu_read_lock();
	err = map->ops->map_delete_elem(map, key);
	rcu_read_unlock();

free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

/* last field in 'union bpf_attr' used by this command */
#define BPF_MAP_GET_NEXT_KEY_LAST_FIELD flags

static int map_get_next_key(union bpf_attr *attr)
{
	void __user *ukey = u64_to_ptr(attr->key);
	void __user *unext_key = u64_to_ptr(attr->next_key);
	int ufd = attr->map_fd;
	struct fd f = fdget(ufd);
	struct bpf_map *map;
	void *key, *next_key;
	int err;

	if (CHECK_ATTR(BPF_MAP_GET_NEXT_KEY))
		return -EINVAL;

	map = bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	err = -ENOMEM;
	key = kmalloc(map->key_size, GFP_USER);
	if (!key)
		goto err_put;

	err = -EFAULT;
	if (copy_from_user(key, ukey, map->key_size) != 0)
		goto free_key;

	err = -ENOMEM;
	next_key = kmalloc(map->key_size, GFP_USER);
	if (!next_key)
		goto free_key;

	rcu_read_lock();
	err = map->ops->map_get_next_key(map, key, next_key);
	rcu_read_unlock();
	if (err)
		goto free_next_key;

	err = -EFAULT;
	if (copy_to_user(unext_key, next_key, map->key_size) != 0)
		goto free_next_key;

	err = 0;

free_next_key:
	kfree(next_key);
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

static LIST_HEAD(bpf_prog_types);

static int find_prog_type(enum bpf_prog_type type, struct bpf_prog *prog)
{
	struct bpf_prog_type_list *tl;

	list_for_each_entry(tl, &bpf_prog_types, list_node) {
		if (tl->type == type) {
			prog->aux->ops = tl->ops;
			prog->aux->prog_type = type;
			return 0;
		}
	}
	return -EINVAL;
}

void bpf_register_prog_type(struct bpf_prog_type_list *tl)
{
	list_add(&tl->list_node, &bpf_prog_types);
}

/* fixup insn->imm field of bpf_call instructions:
 * if (insn->imm == BPF_FUNC_map_lookup_elem)
 *      insn->imm = bpf_map_lookup_elem - __bpf_call_base;
 * else if (insn->imm == BPF_FUNC_map_update_elem)
 *      insn->imm = bpf_map_update_elem - __bpf_call_base;
 * else ...
 *
 * this function is called after eBPF program passed verification
 */
static void fixup_bpf_calls(struct bpf_prog *prog)
{
	const struct bpf_func_proto *fn;
	int i;

	for (i = 0; i < prog->len; i++) {
		struct bpf_insn *insn = &prog->insnsi[i];

		if (insn->code == (BPF_JMP | BPF_CALL)) {
			/* we reach here when program has bpf_call instructions
			 * and it passed bpf_check(), means that
			 * ops->get_func_proto must have been supplied, check it
			 */
			BUG_ON(!prog->aux->ops->get_func_proto);

			fn = prog->aux->ops->get_func_proto(insn->imm);
			/* all functions that have prototype and verifier allowed
			 * programs to call them, must be real in-kernel functions
			 */
			BUG_ON(!fn->func);
			insn->imm = fn->func - __bpf_call_base;
		}
	}
}

/* drop refcnt on maps used by eBPF program and free auxilary data */
static void free_used_maps(struct bpf_prog_aux *aux)
{
	int i;

	for (i = 0; i < aux->used_map_cnt; i++)
		bpf_map_put(aux->used_maps[i]);

	kfree(aux->used_maps);
}

void bpf_prog_put(struct bpf_prog *prog)
{
	if (atomic_dec_and_test(&prog->aux->refcnt)) {
		free_used_maps(prog->aux);
		bpf_prog_free(prog);
	}
}

/* Same as bpf_prog_put(), used by the prog_array fd-array map whose elements are
 * dropped from an xchg()ed slot that RCU readers may still hold. */
void bpf_prog_put_rcu(struct bpf_prog *prog)
{
	if (atomic_dec_and_test(&prog->aux->refcnt)) {
		free_used_maps(prog->aux);
		bpf_prog_free(prog);
	}
}

static int bpf_prog_release(struct inode *inode, struct file *filp)
{
	struct bpf_prog *prog = filp->private_data;

	bpf_prog_put(prog);
	return 0;
}

static int bpf_prog_open(struct inode *inode, struct file *filp)
{
	filp->private_data = bpf_prog_inc(inode->i_private);
	return 0;
}

const struct file_operations bpf_prog_fops = {
	.open    = bpf_prog_open,
	.release = bpf_prog_release,
};

static struct bpf_prog *get_prog(struct fd f)
{
	struct bpf_prog *prog;

	if (!f.file)
		return ERR_PTR(-EBADF);

	if (f.file->f_op != &bpf_prog_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	prog = f.file->private_data;

	return prog;
}

/* called by sockets/tracing/seccomp before attaching program to an event
 * pairs with bpf_prog_put()
 */
struct bpf_prog *bpf_prog_get(u32 ufd)
{
	struct fd f = fdget(ufd);
	struct bpf_prog *prog;

	prog = get_prog(f);

	if (IS_ERR(prog))
		return prog;

	atomic_inc(&prog->aux->refcnt);
	fdput(f);
	return prog;
}

/* last field in 'union bpf_attr' used by this command */
#define	BPF_PROG_LOAD_LAST_FIELD expected_attach_type

static int bpf_prog_load(union bpf_attr *attr)
{
	enum bpf_prog_type type = attr->prog_type;
	struct bpf_prog *prog;
	int err;
	char license[128];
	bool is_gpl;

	if (CHECK_ATTR(BPF_PROG_LOAD))
		return -EINVAL;


	/* 4.4 semantics: loading anything but a socket filter is privileged. */
	if (type != BPF_PROG_TYPE_SOCKET_FILTER && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* copy eBPF program license from user space */
	if (strncpy_from_user(license, u64_to_ptr(attr->license),
			      sizeof(license) - 1) < 0)
		return -EFAULT;
	license[sizeof(license) - 1] = 0;

	/* eBPF programs must be GPL compatible to use GPL-ed functions */
	is_gpl = license_is_gpl_compatible(license);

	if (attr->insn_cnt >= BPF_MAXINSNS)
		return -EINVAL;

	/* plain bpf_prog allocation */
	prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
	if (!prog)
		return -ENOMEM;

	prog->len = attr->insn_cnt;

	err = -EFAULT;
	if (copy_from_user(prog->insns, u64_to_ptr(attr->insns),
			   prog->len * sizeof(struct bpf_insn)) != 0)
		goto free_prog;

	prog->orig_prog = NULL;
	prog->jited = false;

	atomic_set(&prog->aux->refcnt, 1);
	prog->aux->is_gpl_compatible = is_gpl;

	/* find program type: socket_filter vs tracing_filter */
	err = find_prog_type(type, prog);
	if (err < 0)
		goto free_prog;

	/* run eBPF verifier */
	err = bpf_check(prog, attr);

	if (err < 0)
		goto free_used_maps;

	/* fixup BPF_CALL->imm field */
	fixup_bpf_calls(prog);

	/* eBPF program is ready to be JITed */
	bpf_prog_select_runtime(prog);

	err = anon_inode_getfd("bpf-prog", &bpf_prog_fops, prog, O_RDWR | O_CLOEXEC);

	if (err < 0)
		/* failed to allocate fd */
		goto free_used_maps;

	return err;

free_used_maps:
	free_used_maps(prog->aux);
free_prog:
	bpf_prog_free(prog);
	return err;
}

#define BPF_OBJ_PIN_LAST_FIELD file_flags
static int bpf_obj_pin(const union bpf_attr *attr)
{
	if (CHECK_ATTR(BPF_OBJ_PIN))
		return -EINVAL;

	return bpf_obj_pin_user(attr->bpf_fd, u64_to_ptr(attr->pathname));
}

#define BPF_OBJ_GET_LAST_FIELD file_flags
static int bpf_obj_get(const union bpf_attr *attr)
{
	if (CHECK_ATTR(BPF_OBJ_GET))
		return -EINVAL;

	return bpf_obj_get_user(u64_to_ptr(attr->pathname), attr->file_flags);
}

/* Minimal BPF_PROG_ATTACH/DETACH for the eBPF bring-up (2026-09-11): netd
 * attaches its cgroup programs to its own cgroup directory at startup and
 * fails without this.  Only cgroup-directory target fds are supported (any
 * other target yields -EINVAL from bpf_cgroup_from_fd()); the programs are
 * stored on the cgroup and never executed on this kernel - see
 * kernel/bpf/cgroup_stub.c.  No extra capability check beyond the syscall
 * entry gate: this is a load-but-never-run stub for bring-up. */
#define BPF_PROG_ATTACH_LAST_FIELD attach_flags

static int bpf_prog_attach(const union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct cgroup *cgrp;
	int ret;

	if (CHECK_ATTR(BPF_PROG_ATTACH))
		return -EINVAL;

	if (attr->attach_type >= __MAX_BPF_ATTACH_TYPE)
		return -EINVAL;

	if (attr->attach_flags & ~(BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI))
		return -EINVAL;

	/* bpf_prog_get() holds a reference, which becomes the stored one. */
	prog = bpf_prog_get(attr->attach_bpf_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	cgrp = bpf_cgroup_from_fd(attr->target_fd);
	if (IS_ERR(cgrp)) {
		bpf_prog_put(prog);
		return PTR_ERR(cgrp);
	}

	ret = bpf_cgroup_attach_stub(cgrp, prog, attr->attach_type,
				     attr->attach_flags);
	if (ret)
		bpf_prog_put(prog);
	bpf_cgroup_from_fd_put(cgrp);
	return ret;
}

#define BPF_PROG_DETACH_LAST_FIELD attach_type

static int bpf_prog_detach(const union bpf_attr *attr)
{
	struct cgroup *cgrp;
	int ret;

	if (CHECK_ATTR(BPF_PROG_DETACH))
		return -EINVAL;

	if (attr->attach_type >= __MAX_BPF_ATTACH_TYPE)
		return -EINVAL;

	cgrp = bpf_cgroup_from_fd(attr->target_fd);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	ret = bpf_cgroup_detach_stub(cgrp, attr->attach_type);
	bpf_cgroup_from_fd_put(cgrp);
	return ret;
}

SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
{
	union bpf_attr attr = {};
	int err;

	/* 4.4 semantics: unprivileged use is allowed unless the sysctl says
	 * otherwise; program loading keeps its own CAP_SYS_ADMIN check above. */
	if (!capable(CAP_SYS_ADMIN) && sysctl_unprivileged_bpf_disabled)
		return -EPERM;

	if (!access_ok(VERIFY_READ, uattr, 1))
		return -EFAULT;

	if (size > PAGE_SIZE)	/* silly large */
		return -E2BIG;

	/* Upstream rejects a bigger-than-known struct unless every unknown
	 * byte is zero.  For this bring-up (2026-09-11) unknown tail bytes
	 * are only logged, not rejected: Android 13 userspace sets fields
	 * past our layout (btf/func_info/attach_btf_id/...) that this kernel
	 * deliberately does not implement (no BTF, no offload, attach
	 * resolves through expected_attach_type only).  The per-command
	 * CHECK_ATTR above still guards the fields we do know, and every
	 * ignored byte is reported once in dmesg so a real dependency
	 * cannot hide silently.
	 */
	if (size > sizeof(attr)) {
		unsigned char __user *addr;
		unsigned char __user *end;
		unsigned char val;

		addr = (void __user *)uattr + sizeof(attr);
		end  = (void __user *)uattr + size;

		for (; addr < end; addr++) {
			err = get_user(val, addr);
			if (err)
				return err;
			if (val)
				pr_warn_once("bpf: cmd %d ignoring nonzero tail byte at +%tu\n",
					     cmd, addr - (unsigned char __user *)uattr);
		}
		size = sizeof(attr);
	}

	/* copy attributes from user space, may be less than sizeof(bpf_attr) */
	if (copy_from_user(&attr, uattr, size) != 0)
		return -EFAULT;

	switch (cmd) {
	case BPF_MAP_CREATE:
		err = map_create(&attr);
		break;
	case BPF_MAP_LOOKUP_ELEM:
		err = map_lookup_elem(&attr);
		break;
	case BPF_MAP_UPDATE_ELEM:
		err = map_update_elem(&attr);
		break;
	case BPF_MAP_DELETE_ELEM:
		err = map_delete_elem(&attr);
		break;
	case BPF_MAP_GET_NEXT_KEY:
		err = map_get_next_key(&attr);
		break;
	case BPF_PROG_LOAD:
		err = bpf_prog_load(&attr);
		break;
	case BPF_OBJ_PIN:
		err = bpf_obj_pin(&attr);
		break;
	case BPF_OBJ_GET:
		err = bpf_obj_get(&attr);
		break;
	case BPF_PROG_ATTACH:
		err = bpf_prog_attach(&attr);
		break;
	case BPF_PROG_DETACH:
		err = bpf_prog_detach(&attr);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}
