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
#include <linux/rcupdate.h>
#include <linux/random.h>
#include <linux/smp.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/err.h>

/* If kernel subsystem is allowing eBPF programs to call this function,
 * inside its own verifier_ops->get_func_proto() callback it should return
 * bpf_map_lookup_elem_proto, so that verifier can properly check the arguments
 *
 * Different map implementations will rely on rcu in map methods
 * lookup/update/delete, therefore eBPF programs must run under rcu lock
 * if program is allowed to access maps, so check rcu_read_lock_held in
 * all three functions.
 */
static u64 bpf_map_lookup_elem(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	/* verifier checked that R1 contains a valid pointer to bpf_map
	 * and R2 points to a program stack and map->key_size bytes were
	 * initialized
	 */
	struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
	void *key = (void *) (unsigned long) r2;
	void *value;

	WARN_ON_ONCE(!rcu_read_lock_held());

	value = map->ops->map_lookup_elem(map, key);

	/* lookup() returns either pointer to element value or NULL
	 * which is the meaning of PTR_TO_MAP_VALUE_OR_NULL type
	 */
	return (unsigned long) value;
}

const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

static u64 bpf_map_update_elem(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
	void *key = (void *) (unsigned long) r2;
	void *value = (void *) (unsigned long) r3;

	WARN_ON_ONCE(!rcu_read_lock_held());

	return map->ops->map_update_elem(map, key, value, r4);
}

const struct bpf_func_proto bpf_map_update_elem_proto = {
	.func		= bpf_map_update_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

static u64 bpf_map_delete_elem(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
	void *key = (void *) (unsigned long) r2;

	WARN_ON_ONCE(!rcu_read_lock_held());

	return map->ops->map_delete_elem(map, key);
}

const struct bpf_func_proto bpf_map_delete_elem_proto = {
	.func		= bpf_map_delete_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

/* 4.4 uses bpf_user_rnd_u32() (a per-task seed added in 4.1); 3.18 has only
 * the kernel PRNG, which is what the helper is used for anyway. */
static u64 bpf_get_prandom_u32(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return prandom_u32();
}

const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	.func		= bpf_get_prandom_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

static u64 bpf_get_smp_processor_id(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return raw_smp_processor_id();
}

const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
	.func		= bpf_get_smp_processor_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

static u64 bpf_ktime_get_ns(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	/* NMI safe access to clock monotonic */
	return ktime_get_mono_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	.func		= bpf_ktime_get_ns,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};

static u64 bpf_get_current_pid_tgid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct task_struct *task = current;

	if (!task)
		return -EINVAL;

	return (u64) task->tgid << 32 | task->pid;
}

const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	.func		= bpf_get_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

static u64 bpf_get_current_uid_gid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct task_struct *task = current;
	kuid_t uid;
	kgid_t gid;

	if (!task)
		return -EINVAL;

	current_uid_gid(&uid, &gid);
	return (u64) from_kgid(&init_user_ns, gid) << 32 |
		from_kuid(&init_user_ns, uid);
}

const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	.func		= bpf_get_current_uid_gid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

static u64 bpf_get_current_comm(u64 r1, u64 size, u64 r3, u64 r4, u64 r5)
{
	struct task_struct *task = current;
	char *buf = (char *) (long) r1;

	if (!task)
		return -EINVAL;

	strlcpy(buf, task->comm, min_t(size_t, size, sizeof(task->comm)));
	return 0;
}

const struct bpf_func_proto bpf_get_current_comm_proto = {
	.func		= bpf_get_current_comm,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_STACK,
	.arg2_type	= ARG_CONST_STACK_SIZE,
};

/* ------------------------------------------------------------------ */
/* skb-ish helpers for the tethering/netd objects (bring-up 2026-09-11) */
/* ------------------------------------------------------------------ */

/* The programs that call these helpers (tethering offload.o, clatd.o,
 * dscpPolicy.o, netd.o) are verified and loaded so that bpfloader can pin
 * them, but they are never attached or executed on this kernel: there is no
 * XDP/TC data path in 3.18 and BPF_PROG_ATTACH only stores the program (see
 * kernel/bpf/cgroup_stub.c).  The skb-surgery helpers below are therefore
 * bring-up stubs with the correct u64 fn(u64,u64,u64,u64,u64) signature that
 * return -EOPNOTSUPP (0 for redirect, which has "no redirect target" as its
 * honest no-op answer).  Their proto shapes are copied from the 4.4 donor
 * net/core/filter.c (4.9 donor for the helpers 4.4 does not have yet:
 * skb_load_bytes, skb_pull_data, csum_update, skb_change_proto,
 * get_socket_cookie, get_socket_uid); the 3.18 verifier only understands
 * ARG_PTR_TO_CTX because this chunk teaches it that one new arg type, so the
 * 4.9 ARG_PTR_TO_RAW_STACK/ARG_CONST_STACK_SIZE_OR_ZERO spellings are mapped
 * to ARG_PTR_TO_STACK/ARG_CONST_STACK_SIZE. */

static u64 bpf_skb_store_bytes_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_skb_store_bytes_proto = {
	.func		= bpf_skb_store_bytes_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_STACK,
	.arg4_type	= ARG_CONST_STACK_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

static u64 bpf_l3_csum_replace_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_l3_csum_replace_proto = {
	.func		= bpf_l3_csum_replace_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

static u64 bpf_l4_csum_replace_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_l4_csum_replace_proto = {
	.func		= bpf_l4_csum_replace_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

static u64 bpf_redirect_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return 0;
}

const struct bpf_func_proto bpf_redirect_proto = {
	.func		= bpf_redirect_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
};

static u64 bpf_skb_load_bytes_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_skb_load_bytes_proto = {
	.func		= bpf_skb_load_bytes_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_STACK_SIZE,
};

static u64 bpf_skb_change_proto_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_skb_change_proto_proto = {
	.func		= bpf_skb_change_proto_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

static u64 bpf_skb_pull_data_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_skb_pull_data_proto = {
	.func		= bpf_skb_pull_data_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

static u64 bpf_csum_update_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_csum_update_proto = {
	.func		= bpf_csum_update_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

static u64 bpf_skb_change_head_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_skb_change_head_proto = {
	.func		= bpf_skb_change_head_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Bring-up stub: a real get_socket_cookie() returns skb->sk's sk_cookie, but
 * 3.18's struct sock has no sk_cookie field, and the programs calling it are
 * never executed on this kernel, so 0 (upstream's "no socket" answer) keeps
 * netd's dscpPolicy.o loadable. */
static u64 bpf_get_socket_cookie_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return 0;
}

const struct bpf_func_proto bpf_get_socket_cookie_proto = {
	.func		= bpf_get_socket_cookie_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Bring-up stub: a real get_socket_uid() returns the owning socket's uid via
 * sk->sk_uid, but 3.18's struct sock has no sk_uid field, and the programs
 * calling it are never executed on this kernel, so overflowuid (upstream's
 * "no socket" answer) keeps netd.o loadable. */
static u64 bpf_get_socket_uid_stub(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return overflowuid;
}

const struct bpf_func_proto bpf_get_socket_uid_proto = {
	.func		= bpf_get_socket_uid_stub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Real implementation, unlike the stubs above: 3.18's timekeeping already
 * provides ktime_get_boot_ns() (CLOCK_BOOTTIME, i.e. monotonic plus suspend
 * time), which is exactly what upstream's helper returns. */
static u64 bpf_ktime_get_boot_ns(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return ktime_get_boot_ns();
}

const struct bpf_func_proto bpf_ktime_get_boot_ns_proto = {
	.func		= bpf_ktime_get_boot_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
