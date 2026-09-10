/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H 1

#include <uapi/linux/bpf.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/cpumask.h>

struct bpf_map;

/* map is generic key/value storage optionally accesible by eBPF programs */
struct bpf_map_ops {
	/* funcs callable from userspace (via syscall) */
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);

	/* Per-CPU maps (PERCPU_HASH/PERCPU_ARRAY) hold one value per CPU inside
	 * a single element value block of map->value_size bytes.  The syscall
	 * layer must see that whole block - the userspace ABI is
	 * "BPF_MAP_LOOKUP_ELEM fills value_size * num_possible_cpus() bytes
	 * packed by CPU index and BPF_MAP_UPDATE_ELEM consumes the same" - while
	 * a program may only touch the current CPU's slice.  For those maps the
	 * plain hooks below are the program-facing slice variants and these two
	 * are the whole-block ones; syscall.c prefers them when they are set.
	 * NULL means the plain hook has the syscall semantics as well, which is
	 * the case for every other map type (backport 2026-09-11). */
	void *(*map_lookup_elem_sys_only)(struct bpf_map *map, void *key);
	int (*map_update_elem_sys_only)(struct bpf_map *map, void *key,
					void *value, u64 flags);

	/* funcs callable from userspace and from eBPF programs.
	 * The update prototype carries the BPF_ANY/BPF_NOEXIST/BPF_EXIST flag,
	 * as in 4.4 - the map implementations ported from there rely on it. */
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	int (*map_update_elem)(struct bpf_map *map, void *key, void *value,
			       u64 flags);
	int (*map_delete_elem)(struct bpf_map *map, void *key);

	/* funcs called by prog_array and perf_event_array map */
	void *(*map_fd_get_ptr)(struct bpf_map *map, int fd);
	void (*map_fd_put_ptr)(void *ptr);
};

struct bpf_map {
	atomic_t refcnt;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 pages;		/* memory footprint, reported by the map impls */
	const struct bpf_map_ops *ops;
	struct work_struct work;
};

/* How much of an element's value a *program* may see: for the per-CPU map
 * types that is one CPU's slice of the map->value_size block, for every other
 * type the whole value.  The per-CPU map implementations use this for the
 * slice arithmetic of their map_lookup_elem()/map_update_elem(), and the
 * verifier uses it to bound value accesses through a looked-up pointer and the
 * stack buffer passed to BPF_FUNC_map_update_elem - a program can never put the
 * whole per-CPU block (e.g. 10 CPUs * 256 B for time_in_state.o) on its
 * 512-byte stack. */
static inline u32 bpf_map_prog_value_size(const struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		return map->value_size / num_possible_cpus();

	return map->value_size;
}

/* Array of arbitrary sized elements, optionally an array of map/program fds
 * (BPF_MAP_TYPE_PROG_ARRAY / PERF_EVENT_ARRAY / CGROUP_ARRAY). */
struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	enum bpf_prog_type owner_prog_type;
	bool owner_jited;
	union {
		char value[0] __aligned(8);
		void *ptrs[0] __aligned(8);
		void __percpu *pptrs[0] __aligned(8);
	};
};

struct bpf_map_type_list {
	struct list_head list_node;
	const struct bpf_map_ops *ops;
	enum bpf_map_type type;
};

void bpf_register_map_type(struct bpf_map_type_list *tl);
void bpf_map_put(struct bpf_map *map);
struct bpf_map *bpf_map_get(struct fd f);

/* Object pinning / bpffs support (backport 2026-09-10). */
struct bpf_map *bpf_map_inc(struct bpf_map *map, bool uref);
void bpf_map_put_with_uref(struct bpf_map *map);
struct bpf_map *bpf_map_get_with_uref(u32 ufd);
int bpf_map_new_fd(struct bpf_map *map);
struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog);
int bpf_prog_new_fd(struct bpf_prog *prog);
bool bpf_prog_array_compatible(struct bpf_array *array,
			       const struct bpf_prog *fp);
void bpf_prog_put_rcu(struct bpf_prog *prog);
int bpf_obj_pin_user(u32 ufd, const char __user *pathname);
int bpf_get_file_flag(int flags);
int bpf_obj_get_user(const char __user *pathname, int flags);

/* The pinned objects are handed out as ordinary bpf fds, so the bpf
 * filesystem uses these very file_operations on its inodes. */
extern const struct file_operations bpf_map_fops;
extern const struct file_operations bpf_prog_fops;

/* function argument constraints */
enum bpf_arg_type {
	ARG_DONTCARE = 0,	/* unused argument in helper function */

	/* the following constraints used to prototype
	 * bpf_map_lookup/update/delete_elem() functions
	 */
	ARG_CONST_MAP_PTR,	/* const argument used as pointer to bpf_map */
	ARG_PTR_TO_MAP_KEY,	/* pointer to stack used as map key */
	ARG_PTR_TO_MAP_VALUE,	/* pointer to stack used as map value */

	/* the following constraints used to prototype bpf_memcmp() and other
	 * functions that access data on eBPF program stack
	 */
	ARG_PTR_TO_STACK,	/* any pointer to eBPF program stack */
	ARG_CONST_STACK_SIZE,	/* number of bytes accessed from stack */

	ARG_ANYTHING,		/* any (initialized) argument is ok */

	/* ARG_PTR_TO_CTX was added by the 2026-09-11 bring-up chunk: the 4.4
	 * donor protos for the skb helpers type their skb argument with it,
	 * and without it the verifier rejects those protos as
	 * "unsupported arg_type".  Appended last so existing values keep
	 * their ABI. */
	ARG_PTR_TO_CTX,		/* reg points to bpf_context (PTR_TO_CTX) */
	/* Output buffer on the stack: bounds-checked like ARG_PTR_TO_STACK
	 * but the slots need not be initialized (backport 2026-09-11).
	 * Upstream calls this ARG_PTR_TO_UNINIT_MEM; bpf_skb_load_bytes()
	 * and friends prototype their destination buffer with it. */
	ARG_PTR_TO_UNINIT_MEM,
};

/* type of values returned from helper functions */
enum bpf_return_type {
	RET_INTEGER,			/* function returns integer */
	RET_VOID,			/* function doesn't return anything */
	RET_PTR_TO_MAP_VALUE_OR_NULL,	/* returns a pointer to map elem value or NULL */
};

/* eBPF function prototype used by verifier to allow BPF_CALLs from eBPF programs
 * to in-kernel helper functions and for adjusting imm32 field in BPF_CALL
 * instructions after verifying
 */
struct bpf_func_proto {
	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
	bool gpl_only;
	enum bpf_return_type ret_type;
	enum bpf_arg_type arg1_type;
	enum bpf_arg_type arg2_type;
	enum bpf_arg_type arg3_type;
	enum bpf_arg_type arg4_type;
	enum bpf_arg_type arg5_type;
};

/* Helper prototypes implemented in kernel/bpf/helpers.c.  A program type's
 * get_func_proto() hands them to the verifier, which is what allows the
 * Android 13 objects to pass verification (backport 2026-09-10). */
extern const struct bpf_func_proto bpf_map_lookup_elem_proto;
extern const struct bpf_func_proto bpf_map_update_elem_proto;
extern const struct bpf_func_proto bpf_map_delete_elem_proto;
extern const struct bpf_func_proto bpf_get_prandom_u32_proto;
extern const struct bpf_func_proto bpf_get_smp_processor_id_proto;
extern const struct bpf_func_proto bpf_ktime_get_ns_proto;
extern const struct bpf_func_proto bpf_get_current_pid_tgid_proto;
extern const struct bpf_func_proto bpf_get_current_uid_gid_proto;
extern const struct bpf_func_proto bpf_get_current_comm_proto;
/* skb-ish + socket + clock helpers for the tethering/netd objects.  The
 * skb-surgery ones are bring-up stubs (programs are verified and loaded but
 * never attached/executed on this kernel); their proto shapes are copied from
 * the 4.4 donor net/core/filter.c (4.9 donor for the newer ones), see
 * kernel/bpf/helpers.c.  (backport 2026-09-11) */
extern const struct bpf_func_proto bpf_skb_store_bytes_proto;
extern const struct bpf_func_proto bpf_l3_csum_replace_proto;
extern const struct bpf_func_proto bpf_l4_csum_replace_proto;
extern const struct bpf_func_proto bpf_redirect_proto;
extern const struct bpf_func_proto bpf_skb_load_bytes_proto;
extern const struct bpf_func_proto bpf_skb_change_proto_proto;
extern const struct bpf_func_proto bpf_skb_pull_data_proto;
extern const struct bpf_func_proto bpf_csum_update_proto;
extern const struct bpf_func_proto bpf_skb_change_head_proto;
extern const struct bpf_func_proto bpf_get_socket_cookie_proto;
extern const struct bpf_func_proto bpf_get_socket_uid_proto;
extern const struct bpf_func_proto bpf_ktime_get_boot_ns_proto;

/* bpf_context is intentionally undefined structure. Pointer to bpf_context is
 * the first argument to eBPF programs.
 * For socket filters: 'struct bpf_context *' == 'struct sk_buff *'
 */
struct bpf_context;

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2
};

struct bpf_verifier_ops {
	/* return eBPF function prototype for verification */
	const struct bpf_func_proto *(*get_func_proto)(enum bpf_func_id func_id);

	/* return true if 'size' wide access at offset 'off' within bpf_context
	 * with 'type' (read or write) is allowed
	 */
	bool (*is_valid_access)(int off, int size, enum bpf_access_type type);
};

struct bpf_prog_type_list {
	struct list_head list_node;
	const struct bpf_verifier_ops *ops;
	enum bpf_prog_type type;
};

void bpf_register_prog_type(struct bpf_prog_type_list *tl);

struct bpf_prog;

struct bpf_prog_aux {
	atomic_t refcnt;
	bool is_gpl_compatible;
	enum bpf_prog_type prog_type;
	const struct bpf_verifier_ops *ops;
	struct bpf_map **used_maps;
	u32 used_map_cnt;
	struct bpf_prog *prog;
	struct work_struct work;
};

void bpf_prog_put(struct bpf_prog *prog);
struct bpf_prog *bpf_prog_get(u32 ufd);
/* verify correctness of eBPF program */
int bpf_check(struct bpf_prog *fp, union bpf_attr *attr);

struct cgroup;	/* kernel/bpf/cgroup_stub.c, no include cycle this way */

/* Minimal BPF_PROG_ATTACH/DETACH plumbing (backport 2026-09-11).  The run
 * path is deliberately stubbed: attached programs are stored on the cgroup
 * and never executed (no packet-path hooks on 3.18). */
struct cgroup *bpf_cgroup_from_fd(int fd);
void bpf_cgroup_from_fd_put(struct cgroup *cgrp);
int bpf_cgroup_attach_stub(struct cgroup *cgrp, struct bpf_prog *prog,
			   u32 type, u32 flags);
int bpf_cgroup_detach_stub(struct cgroup *cgrp, u32 type);

#endif /* _LINUX_BPF_H */
