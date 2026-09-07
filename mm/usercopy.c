/*
 * This implements the various checks for CONFIG_HARDENED_USERCOPY*,
 * which are designed to protect kernel memory from needless exposure
 * and overwrite under many unintended conditions. This code is based
 * on PAX_USERCOPY, which is:
 *
 * Copyright (C) 2001-2016 PaX Team, Bradley Spengler, Open Source
 * Security Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/sections.h>

enum {
	BAD_STACK = -1,
	NOT_STACK = 0,
	GOOD_FRAME,
	GOOD_STACK,
};

/*
 * Checks if a given pointer and length is contained by the current
 * stack frame (if possible).
 *
 * Returns:
 *	NOT_STACK: not at all on the stack
 *	GOOD_FRAME: fully within a valid stack frame
 *	GOOD_STACK: fully on the stack (when can't do frame-checking)
 *	BAD_STACK: error condition (invalid stack position or bad stack frame)
 */
static noinline int check_stack_object(const void *obj, unsigned long len)
{
	const void * const stack = task_stack_page(current);
	const void * const stackend = stack + THREAD_SIZE;
	int ret;

	/* Object is not on the stack at all. */
	if (obj + len <= stack || stackend <= obj)
		return NOT_STACK;

	/*
	 * Reject: object partially overlaps the stack (passing the
	 * the check above means at least one end is within the stack,
	 * so if this check fails, the other end is outside the stack).
	 */
	if (obj < stack || stackend < obj + len)
		return BAD_STACK;

	/* Check if object is safely within a valid frame. */
	ret = arch_within_stack_frames(stack, stackend, obj, len);
	if (ret)
		return ret;

	return GOOD_STACK;
}

static void report_usercopy(const void *ptr, unsigned long len,
			    bool to_user, const char *type)
{
	pr_emerg("kernel memory %s attempt detected %s %p (%s) (%lu bytes)\n",
		to_user ? "exposure" : "overwrite",
		to_user ? "from" : "to", ptr, type ? : "unknown", len);
	/*
	 * For greater effect, it would be nice to do do_group_exit(),
	 * but BUG() actually hooks all the lock-breaking and per-arch
	 * Oops code, so that is used here instead.
	 */
	BUG();
}

/* Returns true if any portion of [ptr,ptr+n) over laps with [low,high). */
static bool overlaps(const void *ptr, unsigned long n, unsigned long low,
		     unsigned long high)
{
	unsigned long check_low = (uintptr_t)ptr;
	unsigned long check_high = check_low + n;

	/* Does not overlap if entirely above or entirely below. */
	if (check_low >= high || check_high <= low)
		return false;

	return true;
}

/* Is [low,high) -- or its linear-map alias -- hit by [ptr,ptr+n)? */
static inline const char *check_kernel_text_range(const void *ptr,
						  unsigned long n,
						  unsigned long low,
						  unsigned long high)
{
	unsigned long low_linear, high_linear;

	if (low >= high)
		return NULL;

	if (overlaps(ptr, n, low, high))
		return "<kernel text>";

	/*
	 * Some architectures have virtual memory mappings with a secondary
	 * mapping of the kernel text, i.e. there is more than one virtual
	 * kernel address that points to the kernel image. It is usually
	 * when there is a separate linear physical memory mapping, in that
	 * __pa() is not just the reverse of __va(). This can be detected
	 * and checked:
	 */
	low_linear = (unsigned long)__va(__pa(low));
	/* No different mapping: we're done. */
	if (low_linear == low)
		return NULL;

	/* Check the secondary mapping... */
	high_linear = (unsigned long)__va(__pa(high));
	if (overlaps(ptr, n, low_linear, high_linear))
		return "<linear kernel text>";

	return NULL;
}

/*
 * Is this address range in the kernel text area?
 *
 * Upstream assumes [_stext,_etext) contains only executable text, because on
 * the architectures it was written for RO_DATA is linked after _etext. That is
 * NOT true on arm64 before the _etext/RO_DATA split (mainline 4.6): this tree's
 * arch/arm64/kernel/vmlinux.lds.S puts RO_DATA *inside* the range and says so --
 *	_etext = .;   with the comment "End of text and rodata section".
 * With the naive range every copy_to_user() of a string literal is reported as
 * a text exposure. On m95 that killed boot30 in init at 4.855 s:
 *	usercopy: kernel memory exposure attempt detected from
 *	ffffffc0010b53d0 (<kernel text>) (1 bytes)
 * filldir64 <- kernfs_fop_readdir <- iterate_dir <- SyS_getdents64, i.e. the
 * one-byte "." name that dir_emit_dots() hands out of .rodata
 * (__start_rodata=ffffffc000ca2000, __end_rodata=ffffffc0012bf000).
 *
 * So carve the read-only data out of the range and reproduce the mainline
 * semantics "text does not include rodata". The alternative -- backporting the
 * arm64 linker change that moves _etext ahead of RO_DATA -- would also resize
 * the RO/NX mapping built from _etext-_stext in arch/arm64/mm/mmu.c and the
 * kernel_code resource in setup.c, which is a much larger blast radius for no
 * extra protection here.
 */
static inline const char *check_kernel_text_object(const void *ptr,
						   unsigned long n)
{
	unsigned long textlow = (unsigned long)_stext;
	unsigned long texthigh = (unsigned long)_etext;
	unsigned long rodatalow = (unsigned long)__start_rodata;
	unsigned long rodatahigh = (unsigned long)__end_rodata;
	const char *err;

	/* Does this arch link RO_DATA inside [_stext,_etext)? */
	if (rodatalow >= textlow && rodatahigh <= texthigh) {
		err = check_kernel_text_range(ptr, n, textlow, rodatalow);
		if (err)
			return err;
		return check_kernel_text_range(ptr, n, rodatahigh, texthigh);
	}

	return check_kernel_text_range(ptr, n, textlow, texthigh);
}

static inline const char *check_bogus_address(const void *ptr, unsigned long n)
{
	/* Reject if object wraps past end of memory. */
	if ((unsigned long)ptr + n < (unsigned long)ptr)
		return "<wrapped address>";

	/* Reject if NULL or ZERO-allocation. */
	if (ZERO_OR_NULL_PTR(ptr))
		return "<null>";

	return NULL;
}

/* Checks for allocs that are marked in some way as spanning multiple pages. */
static inline const char *check_page_span(const void *ptr, unsigned long n,
					  struct page *page, bool to_user)
{
#ifdef CONFIG_HARDENED_USERCOPY_PAGESPAN
	const void *end = ptr + n - 1;
	struct page *endpage;
	bool is_reserved, is_cma;

	/*
	 * Sometimes the kernel data regions are not marked Reserved (see
	 * check below). And sometimes [_sdata,_edata) does not cover
	 * rodata and/or bss, so check each range explicitly.
	 */

	/* Allow reads of kernel rodata region (if not marked as Reserved). */
	if (ptr >= (const void *)__start_rodata &&
	    end <= (const void *)__end_rodata) {
		if (!to_user)
			return "<rodata>";
		return NULL;
	}

	/* Allow kernel data region (if not marked as Reserved). */
	if (ptr >= (const void *)_sdata && end <= (const void *)_edata)
		return NULL;

	/* Allow kernel bss region (if not marked as Reserved). */
	if (ptr >= (const void *)__bss_start &&
	    end <= (const void *)__bss_stop)
		return NULL;

	/* Is the object wholly within one base page? */
	if (likely(((unsigned long)ptr & (unsigned long)PAGE_MASK) ==
		   ((unsigned long)end & (unsigned long)PAGE_MASK)))
		return NULL;

	/* Allow if fully inside the same compound (__GFP_COMP) page. */
	endpage = virt_to_head_page(end);
	if (likely(endpage == page))
		return NULL;

	/*
	 * Reject if range is entirely either Reserved (i.e. special or
	 * device memory), or CMA. Otherwise, reject since the object spans
	 * several independently allocated pages.
	 */
	is_reserved = PageReserved(page);
	is_cma = is_migrate_cma_page(page);
	if (!is_reserved && !is_cma)
		return "<spans multiple pages>";

	for (ptr += PAGE_SIZE; ptr <= end; ptr += PAGE_SIZE) {
		page = virt_to_head_page(ptr);
		if (is_reserved && !PageReserved(page))
			return "<spans Reserved and non-Reserved pages>";
		if (is_cma && !is_migrate_cma_page(page))
			return "<spans CMA and non-CMA pages>";
	}
#endif

	return NULL;
}

static inline const char *check_heap_object(const void *ptr, unsigned long n,
					    bool to_user)
{
	struct page *page;

	/*
	 * Some architectures (arm64) return true for virt_addr_valid() on
	 * vmalloced addresses. Work around this by checking for vmalloc
	 * first.
	 */
	if (is_vmalloc_addr(ptr))
		return NULL;

	if (!virt_addr_valid(ptr))
		return NULL;

	page = virt_to_head_page(ptr);

	/* Check slab allocator for flags and size. */
	if (PageSlab(page))
		return __check_heap_object(ptr, n, page);

	/* Verify object does not incorrectly span multiple pages. */
	return check_page_span(ptr, n, page, to_user);
}

/*
 * Validates that the given object is:
 * - not bogus address
 * - known-safe heap or stack object
 * - not in kernel text
 */
void __check_object_size(const void *ptr, unsigned long n, bool to_user)
{
	const char *err;

	/* Skip all tests if size is zero. */
	if (!n)
		return;

	/* Check for invalid addresses. */
	err = check_bogus_address(ptr, n);
	if (err)
		goto report;

	/* Check for bad heap object. */
	err = check_heap_object(ptr, n, to_user);
	if (err)
		goto report;

	/* Check for bad stack object. */
	switch (check_stack_object(ptr, n)) {
	case NOT_STACK:
		/* Object is not touching the current process stack. */
		break;
	case GOOD_FRAME:
	case GOOD_STACK:
		/*
		 * Object is either in the correct frame (when it
		 * is possible to check) or just generally on the
		 * process stack (when frame checking not available).
		 */
		return;
	default:
		err = "<process stack>";
		goto report;
	}

	/* Check for object in kernel to avoid text exposure. */
	err = check_kernel_text_object(ptr, n);
	if (!err)
		return;

report:
	report_usercopy(ptr, n, to_user, err);
}
EXPORT_SYMBOL(__check_object_size);
