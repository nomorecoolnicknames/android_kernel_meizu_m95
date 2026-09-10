/*
 * Program types for the eBPF backport (2026-09-10).
 *
 * The 3.18.22 MTK tree this kernel comes from registers no program type at all
 * (only kernel/bpf/test_stub.c does, for the BPF_FUNC_unspec selftest), so
 * BPF_PROG_LOAD always failed with -EINVAL and the Android 13 bpfloader could
 * not load a single object.  That in turn left gpuservice without its pinned
 * maps (it aborts inside libbpf_bcc's BpfMap constructor) and netd without its
 * netd_shared programs (libnetd_updatable_init fails), and init rebooted the
 * system after four crashes of each.
 *
 * This implements the program types the Android 13 objects in
 * /system/etc/bpf and the tethering apex are compiled as:
 *
 *   tracepoint/<subsystem>/<event>  -> BPF_PROG_TYPE_TRACEPOINT
 *       gpu_work.o   (helpers 1,2), gpu_mem.o (1,2,3), time_in_state.o
 *       (1,2,3,5,8,14,15), fuse_media.o (6)
 *   schedcls/<name>                 -> BPF_PROG_TYPE_SCHED_CLS
 *       tethering offload.o/test.o
 *
 * plus the bring-up types (XDP, CGROUP_SKB, CGROUP_SOCK, CGROUP_SOCK_ADDR,
 * SCHED_ACT, SOCKET_FILTER) for the tethering/netd objects: those programs
 * are verified and loaded so bpfloader can pin them, but never attached or
 * executed on this kernel (added 2026-09-11).
 *
 * Only what is needed to *verify and load* the programs is provided here: the
 * tracepoint context is read-only program input and the sched_cls helpers are
 * the skb ones already present in net/core/filter.c.  Attaching a tracepoint
 * program to an actual tracepoint needs the perf/trampoline plumbing that 3.18
 * also lacks; the Android side treats a failed attach as non-fatal (it logs
 * "Failed to attach bpf program to <subsystem>/<event> tracepoint").
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/string.h>

/* 4.x defines this in uapi/linux/perf_event.h, which 3.18 does not have; it is
 * the upstream bound for tracepoint context accesses. */
#ifndef PERF_MAX_TRACE_SIZE
#define PERF_MAX_TRACE_SIZE	2048
#endif

/* ------------------------------------------------------------------ */
/* trace_printk (helper 6)                                            */
/* ------------------------------------------------------------------ */

/* The real helper writes into the trace ring buffer.  This kernel has no
 * bpf_trace_printk plumbing (kernel/trace/bpf_trace.c does not exist here), so
 * the message is formatted on the stack and handed to printk().  fuse_media.o
 * only uses it for diagnostics, and a program that calls an unknown helper is
 * rejected outright, so a working stub keeps the object loadable. */
static u64 bpf_trace_printk(u64 r1, u64 r2, u64 fmt_size, u64 r4, u64 r5)
{
	/* Deliberately does not dereference the format pointer: the verifier
	 * types it as ARG_ANYTHING and 3.18 has no strncpy_from_unsafe() to read
	 * a kernel pointer safely.  Logging a fixed line keeps fuse_media.o
	 * loadable without opening an arbitrary-read path from BPF. */
	printk(KERN_INFO "bpf: trace_printk helper called\n");
	return 0;
}

static const struct bpf_func_proto bpf_trace_printk_proto = {
	.func		= bpf_trace_printk,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

const struct bpf_func_proto *bpf_get_trace_printk_proto(void)
{
	return &bpf_trace_printk_proto;
}

/* ------------------------------------------------------------------ */
/* tracepoint programs                                                */
/* ------------------------------------------------------------------ */

/* Upstream 4.4's tp_prog_is_valid_access(): the program gets the tracepoint's
 * argument block, reads only, within PERF_MAX_TRACE_SIZE. */
static bool tp_prog_is_valid_access(int off, int size, enum bpf_access_type type)
{
	if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
		return false;

	if (type != BPF_READ)
		return false;

	if (off % size != 0)
		return false;

	return true;
}

static const struct bpf_func_proto *
tp_prog_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	/* skb-ish helpers for the tethering/netd objects (bring-up
	 * 2026-09-11): protos live in kernel/bpf/helpers.c, the skb-surgery
	 * ones are stubs because the programs are verified and loaded but
	 * never attached/executed on this kernel. */
	case BPF_FUNC_skb_store_bytes:
		return &bpf_skb_store_bytes_proto;
	case BPF_FUNC_l3_csum_replace:
		return &bpf_l3_csum_replace_proto;
	case BPF_FUNC_l4_csum_replace:
		return &bpf_l4_csum_replace_proto;
	case BPF_FUNC_redirect:
		return &bpf_redirect_proto;
	case BPF_FUNC_skb_load_bytes:
		return &bpf_skb_load_bytes_proto;
	case BPF_FUNC_skb_change_proto:
		return &bpf_skb_change_proto_proto;
	case BPF_FUNC_skb_pull_data:
		return &bpf_skb_pull_data_proto;
	case BPF_FUNC_csum_update:
		return &bpf_csum_update_proto;
	case BPF_FUNC_skb_change_head:
		return &bpf_skb_change_head_proto;
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_cookie_proto;
	case BPF_FUNC_get_socket_uid:
		return &bpf_get_socket_uid_proto;
	case BPF_FUNC_ktime_get_boot_ns:
		return &bpf_ktime_get_boot_ns_proto;
	default:
		return NULL;
	}
}

static const struct bpf_verifier_ops tracepoint_prog_ops = {
	.get_func_proto		= tp_prog_func_proto,
	.is_valid_access	= tp_prog_is_valid_access,
};

static struct bpf_prog_type_list tracepoint_tl = {
	.ops	= &tracepoint_prog_ops,
	.type	= BPF_PROG_TYPE_TRACEPOINT,
};

/* ------------------------------------------------------------------ */
/* sched_cls programs                                                 */
/* ------------------------------------------------------------------ */

/* The context of a sched_cls program is the skb; net/core/filter.c owns the
 * access rules and the skb helper table for that, but the 3.18 tree never
 * registered the type.  Until those land, the type is registered with a
 * conservative context rule (the skb fields Android's tethering programs read
 * live in the first PERF_MAX_TRACE_SIZE bytes and are all aligned reads) and
 * the same helper set. */
static bool sched_cls_is_valid_access(int off, int size,
				      enum bpf_access_type type)
{
	if (off < 0 || off >= PERF_MAX_TRACE_SIZE)
		return false;

	if (off % size != 0)
		return false;

	return true;
}

static const struct bpf_verifier_ops sched_cls_prog_ops = {
	.get_func_proto		= tp_prog_func_proto,
	.is_valid_access	= sched_cls_is_valid_access,
};

static struct bpf_prog_type_list sched_cls_tl = {
	.ops	= &sched_cls_prog_ops,
	.type	= BPF_PROG_TYPE_SCHED_CLS,
};

/* ------------------------------------------------------------------ */
/* bring-up program types (2026-09-11)                                */
/* ------------------------------------------------------------------ */

/* XDP, CGROUP_SKB, CGROUP_SOCK, CGROUP_SOCK_ADDR, SCHED_ACT and
 * SOCKET_FILTER programs from the tethering apex and netd_shared are
 * loaded but never executed on this kernel: the XDP/TC/cgroup data paths
 * that would run them do not exist in 3.18, and BPF_PROG_ATTACH only stores
 * the program (see kernel/bpf/cgroup_stub.c).  The context rule below only
 * needs to let the real A13-compiled programs pass verification, so it
 * accepts aligned reads in the first 256 bytes of the context pointer.
 * There is deliberately no convert_ctx_access rewrite (the 3.18 verifier
 * has no such hook). */
#define BRINGUP_CTX_SIZE	256

static bool bringup_prog_is_valid_access(int off, int size,
					 enum bpf_access_type type)
{
	if (size <= 0)
		return false;

	if (off < 0 || off >= BRINGUP_CTX_SIZE)
		return false;

	if (type != BPF_READ)
		return false;

	if (off % size != 0)
		return false;

	return true;
}

static const struct bpf_verifier_ops bringup_prog_ops = {
	.get_func_proto		= tp_prog_func_proto,
	.is_valid_access	= bringup_prog_is_valid_access,
};

static struct bpf_prog_type_list xdp_tl = {
	.ops	= &bringup_prog_ops,
	.type	= BPF_PROG_TYPE_XDP,
};

static struct bpf_prog_type_list cgroup_skb_tl = {
	.ops	= &bringup_prog_ops,
	.type	= BPF_PROG_TYPE_CGROUP_SKB,
};

static struct bpf_prog_type_list cgroup_sock_tl = {
	.ops	= &bringup_prog_ops,
	.type	= BPF_PROG_TYPE_CGROUP_SOCK,
};

static struct bpf_prog_type_list cgroup_sock_addr_tl = {
	.ops	= &bringup_prog_ops,
	.type	= BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
};

static struct bpf_prog_type_list sched_act_tl = {
	.ops	= &bringup_prog_ops,
	.type	= BPF_PROG_TYPE_SCHED_ACT,
};

static struct bpf_prog_type_list socket_filter_tl = {
	.ops	= &bringup_prog_ops,
	.type	= BPF_PROG_TYPE_SOCKET_FILTER,
};

static int __init register_android_prog_types(void)
{
	bpf_register_prog_type(&tracepoint_tl);
	bpf_register_prog_type(&sched_cls_tl);
	bpf_register_prog_type(&xdp_tl);
	bpf_register_prog_type(&cgroup_skb_tl);
	bpf_register_prog_type(&cgroup_sock_tl);
	bpf_register_prog_type(&cgroup_sock_addr_tl);
	bpf_register_prog_type(&sched_act_tl);
	bpf_register_prog_type(&socket_filter_tl);
	return 0;
}
late_initcall(register_android_prog_types);
