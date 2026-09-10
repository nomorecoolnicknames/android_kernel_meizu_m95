/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_H__

#include <linux/types.h>
#include <linux/bpf_common.h>

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word */
#define BPF_XADD	0xc0	/* exclusive add */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

#define BPF_JNE		0x50	/* jump != */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};

/* BPF syscall commands */
enum bpf_cmd {
	/* create a map with given type and attributes
	 * fd = bpf(BPF_MAP_CREATE, union bpf_attr *, u32 size)
	 * returns fd or negative error
	 * map is deleted when fd is closed
	 */
	BPF_MAP_CREATE,

	/* lookup key in a given map
	 * err = bpf(BPF_MAP_LOOKUP_ELEM, union bpf_attr *attr, u32 size)
	 * Using attr->map_fd, attr->key, attr->value
	 * returns zero and stores found elem into value
	 * or negative error
	 */
	BPF_MAP_LOOKUP_ELEM,

	/* create or update key/value pair in a given map
	 * err = bpf(BPF_MAP_UPDATE_ELEM, union bpf_attr *attr, u32 size)
	 * Using attr->map_fd, attr->key, attr->value
	 * returns zero or negative error
	 */
	BPF_MAP_UPDATE_ELEM,

	/* find and delete elem by key in a given map
	 * err = bpf(BPF_MAP_DELETE_ELEM, union bpf_attr *attr, u32 size)
	 * Using attr->map_fd, attr->key
	 * returns zero or negative error
	 */
	BPF_MAP_DELETE_ELEM,

	/* lookup key in a given map and return next key
	 * err = bpf(BPF_MAP_GET_NEXT_KEY, union bpf_attr *attr, u32 size)
	 * Using attr->map_fd, attr->key, attr->next_key
	 * returns zero and stores next key or negative error
	 */
	BPF_MAP_GET_NEXT_KEY,

	/* verify and load eBPF program
	 * prog_fd = bpf(BPF_PROG_LOAD, union bpf_attr *attr, u32 size)
	 * Using attr->prog_type, attr->insns, attr->license
	 * returns fd or negative error
	 */
	BPF_PROG_LOAD,

	/* pin an eBPF object to a file in the bpf filesystem
	 * err = bpf(BPF_OBJ_PIN, union bpf_attr *attr, u32 size)
	 * Using attr->pathname, attr->bpf_fd, attr->file_flags
	 * returns zero or negative error
	 */
	BPF_OBJ_PIN,

	/* get an fd for an object pinned in the bpf filesystem
	 * fd = bpf(BPF_OBJ_GET, union bpf_attr *attr, u32 size)
	 * Using attr->pathname, attr->file_flags
	 * returns fd or negative error
	 */
	BPF_OBJ_GET,

	/* attach/detach an eBPF program to/from a cgroup
	 * err = bpf(BPF_PROG_ATTACH, union bpf_attr *attr, u32 size)
	 * Using attr->target_fd, attr->attach_bpf_fd, attr->attach_type
	 * returns zero or negative error
	 */
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
};

/* Values 0..6 are ABI: they are what Android 13 userspace (bpfloader, netd,
 * libgpuwork) puts into struct bpf_map_def / the ELF section names.  Only
 * UNSPEC, HASH and ARRAY are implemented by this kernel today; the rest are
 * declared so that the numbers line up and the unsupported ones fail loudly
 * instead of silently creating a wrong map. (backport 2026-09-10) */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,	/* 24, ABI placeholder: not implemented */
	BPF_MAP_TYPE_DEVMAP_HASH,	/* 25, tethering offload.o declares one;
					 * XDP/devmap data path does not exist
					 * on 3.18, so this is a HASH alias stub
					 * (backport 2026-09-11) */
};

/* Same ABI rule as above: TRACEPOINT(5) is what the /system/etc/bpf programs
 * (gpu_work, gpu_mem, time_in_state) are compiled as, CGROUP_SKB(8) is what
 * netd pins. */
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER,
	BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE,
	BPF_SK_MSG_VERDICT,
	BPF_CGROUP_INET4_BIND,
	BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT,
	BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND,
	BPF_CGROUP_INET6_POST_BIND,
	__MAX_BPF_ATTACH_TYPE
};

#define BPF_OBJ_NAME_LEN 16U

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY		0 /* create new element or update existing */
#define BPF_NOEXIST	1 /* create new element if it didn't exist */
#define BPF_EXIST	2 /* update existing element */

/* flags for BPF_PROG_ATTACH command (subset of upstream; the run path that
 * would need ALLOW_MULTI lists does not exist on this kernel) */
#define BPF_F_ALLOW_OVERRIDE	(1U << 0)
#define BPF_F_ALLOW_MULTI	(1U << 1)
/* file_flags for BPF_OBJ_GET (and map creation): without these every get
 * demands MAY_WRITE, which breaks non-root readers of 0440 pinned objects
 * (e.g. gpuservice opening root:graphics programs).  Values match upstream. */
#define BPF_F_RDONLY		(1U << 3)
#define BPF_F_WRONLY		(1U << 4)

union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
		__u32	map_type;	/* one of enum bpf_map_type */
		__u32	key_size;	/* size of key in bytes */
		__u32	value_size;	/* size of value in bytes */
		__u32	max_entries;	/* max number of entries in a map */
		__u32	map_flags;	/* BPF_MAP_CREATE related flags */
		__u32	inner_map_fd;	/* fd pointing to the inner map */
		__u32	numa_node;	/* numa node (effective only if
					 * BPF_F_NUMA_NODE is set).
					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		__u32	map_ifindex;	/* ifindex of netdev to create on */
		__u32	btf_fd;		/* fd pointing to a BTF type data */
		__u32	btf_key_type_id;
		__u32	btf_value_type_id;
	};

	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
		__u32		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		__u64		flags;
	};

	struct { /* anonymous struct used by BPF_PROG_LOAD command */
		__u32		prog_type;	/* one of enum bpf_prog_type */
		__u32		insn_cnt;
		__aligned_u64	insns;
		__aligned_u64	license;
		__u32		log_level;	/* verbosity level of verifier */
		__u32		log_size;	/* size of user buffer */
		__aligned_u64	log_buf;	/* user supplied buffer */
		__u32		kern_version;	/* checked when prog_type=kprobe */
		__u32		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
		__u32		prog_ifindex;	/* ifindex of netdev to prep for */
		__u32		expected_attach_type; /* for some prog types */
	};

	struct { /* anonymous struct used by BPF_OBJ_* commands */
		__aligned_u64	pathname;
		__u32		bpf_fd;
		__u32		file_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
		__u32		target_fd;	/* container object to attach to */
		__u32		attach_bpf_fd;	/* eBPF program to attach */
		__u32		attach_type;
		__u32		attach_flags;
	};
} __attribute__((aligned(8)));

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
/* Helper ids are ABI: the numbers below are what Android 13 userspace compiles
 * into BPF_CALL immediates (bpfloader/netd objects in /system/etc/bpf and the
 * tethering apex use ids 1,2,3,5,6,8,9,10,11,14,15,23,26,31,39,40,43,46,47
 * and 125).  The 3.18 tree shipped only BPF_FUNC_unspec, so every helper call
 * failed verification. (backport 2026-09-10, extended 2026-09-11) */
enum bpf_func_id {
	BPF_FUNC_unspec,
	BPF_FUNC_map_lookup_elem,
	BPF_FUNC_map_update_elem,
	BPF_FUNC_map_delete_elem,
	BPF_FUNC_probe_read,
	BPF_FUNC_ktime_get_ns,
	BPF_FUNC_trace_printk,
	BPF_FUNC_get_prandom_u32,
	BPF_FUNC_get_smp_processor_id,
	BPF_FUNC_skb_store_bytes,
	BPF_FUNC_l3_csum_replace,
	BPF_FUNC_l4_csum_replace,
	BPF_FUNC_tail_call,
	BPF_FUNC_clone_redirect,
	BPF_FUNC_get_current_pid_tgid,
	BPF_FUNC_get_current_uid_gid,
	BPF_FUNC_get_current_comm,
	BPF_FUNC_get_cgroup_classid,
	BPF_FUNC_skb_vlan_push,
	BPF_FUNC_skb_vlan_pop,
	BPF_FUNC_skb_get_tunnel_key,
	BPF_FUNC_skb_set_tunnel_key,
	BPF_FUNC_perf_event_read,
	BPF_FUNC_redirect,
	BPF_FUNC_get_route_realm,
	BPF_FUNC_perf_event_output,
	BPF_FUNC_skb_load_bytes,
	BPF_FUNC_get_stackid,
	BPF_FUNC_csum_diff,
	BPF_FUNC_skb_get_tunnel_opt,
	BPF_FUNC_skb_set_tunnel_opt,
	BPF_FUNC_skb_change_proto,
	BPF_FUNC_skb_change_type,
	BPF_FUNC_skb_under_cgroup,
	BPF_FUNC_get_hash_recalc,
	BPF_FUNC_get_current_task,
	BPF_FUNC_probe_write_user,
	BPF_FUNC_current_task_under_cgroup,
	BPF_FUNC_skb_change_tail,
	BPF_FUNC_skb_pull_data,
	BPF_FUNC_csum_update,
	BPF_FUNC_set_hash_invalid,
	BPF_FUNC_get_numa_node_id,
	BPF_FUNC_skb_change_head,
	BPF_FUNC_xdp_adjust_head,
	BPF_FUNC_probe_read_str,
	BPF_FUNC_get_socket_cookie,
	BPF_FUNC_get_socket_uid,
	BPF_FUNC_set_hash,
	BPF_FUNC_setsockopt,
	BPF_FUNC_skb_adjust_room,
	BPF_FUNC_redirect_map,
	BPF_FUNC_sk_redirect_map,
	BPF_FUNC_sock_map_update,
	BPF_FUNC_xdp_adjust_meta,
	BPF_FUNC_perf_event_read_value,
	BPF_FUNC_perf_prog_read_value,
	BPF_FUNC_getsockopt,
	BPF_FUNC_override_return,
	BPF_FUNC_sock_ops_cb_flags_set,
	BPF_FUNC_msg_redirect_map,
	BPF_FUNC_msg_apply_bytes,
	BPF_FUNC_msg_cork_bytes,
	BPF_FUNC_msg_pull_data,
	BPF_FUNC_bind,
	BPF_FUNC_xdp_adjust_tail,
	BPF_FUNC_skb_get_xfrm_state,
	BPF_FUNC_get_stack,
	BPF_FUNC_skb_load_bytes_relative,
	BPF_FUNC_fib_lookup,
	BPF_FUNC_sock_hash_update,
	BPF_FUNC_msg_redirect_hash,
	BPF_FUNC_sk_redirect_hash,
	BPF_FUNC_lwt_push_encap,
	BPF_FUNC_lwt_seg6_store_bytes,
	BPF_FUNC_lwt_seg6_adjust_srh,
	BPF_FUNC_lwt_seg6_action,
	BPF_FUNC_rc_repeat,
	BPF_FUNC_rc_keydown,
	BPF_FUNC_skb_cgroup_id,
	BPF_FUNC_get_current_cgroup_id,
	BPF_FUNC_get_local_storage,
	BPF_FUNC_sk_select_reuseport,
	BPF_FUNC_skb_ancestor_cgroup_id,
	BPF_FUNC_sk_lookup_tcp,
	BPF_FUNC_sk_lookup_udp,
	BPF_FUNC_sk_release,
	BPF_FUNC_map_push_elem,
	BPF_FUNC_map_pop_elem,
	BPF_FUNC_map_peek_elem,
	BPF_FUNC_ktime_get_boot_ns = 125,	/* tethering offload.o calls it;
						 * upstream __BPF_FUNC_MAPPER id */
	__BPF_FUNC_MAX_ID,
};

#endif /* _UAPI__LINUX_BPF_H__ */
