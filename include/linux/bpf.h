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

struct bpf_map;

/* map is generic key/value storage optionally accesible by eBPF programs */
struct bpf_map_ops {
	/* funcs callable from userspace (via syscall) */
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);

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
int bpf_obj_get_user(const char __user *pathname);

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
	struct bpf_verifier_ops *ops;
	enum bpf_prog_type type;
};

void bpf_register_prog_type(struct bpf_prog_type_list *tl);

struct bpf_prog;

struct bpf_prog_aux {
	atomic_t refcnt;
	bool is_gpl_compatible;
	enum bpf_prog_type prog_type;
	struct bpf_verifier_ops *ops;
	struct bpf_map **used_maps;
	u32 used_map_cnt;
	struct bpf_prog *prog;
	struct work_struct work;
};

void bpf_prog_put(struct bpf_prog *prog);
struct bpf_prog *bpf_prog_get(u32 ufd);
/* verify correctness of eBPF program */
int bpf_check(struct bpf_prog *fp, union bpf_attr *attr);

#endif /* _LINUX_BPF_H */
