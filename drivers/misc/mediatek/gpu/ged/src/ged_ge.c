/*
 * Copyright (C) 2015 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/slab.h>
#include <linux/sched.h>   /* current->pid / current->comm, M95GE trace */
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/stddef.h>

#include "ged_base.h"
#include "ged_bridge.h"
#include "ged_debugFS.h"
#include "ged_ge.h"

typedef struct {
	int ver;
	int ref;
	int region_num;

	void *data;
	uint32_t *region_sizes;	/* sub data, points into ->data */
	uint32_t **region_data;	/* sub data, points into ->data */
} GEEntry;

#define GE_PERR(fmt, ...) \
	pr_err("[GRALLOC_EXTRA,%s:%d]" fmt, __FILE__, __LINE__, ##__VA_ARGS__)

typedef struct {
	GED_FILE_PRIVATE_BASE base;
	int16_t ref_table[GE_POOL_ENTRY_SIZE];
} GED_GE_FILE;

static struct kmem_cache *gPoolCache;
static uint16_t gver = 1;
static GEEntry *gPoolEntry[GE_POOL_ENTRY_SIZE];
static DEFINE_MUTEX(gPoolMutex);

static struct dentry *gDFSEntry;

/*****************************************************************************
 *  debugfs: /d/ged/ge
 *****************************************************************************/

static void *_get_debugfs_seq_nextx(loff_t *pos)
{
	loff_t n = *pos - 1;

	return (n >= GE_POOL_ENTRY_SIZE) ? NULL : &gPoolEntry[n];
}

static void *_ge_debugfs_seq_start(struct seq_file *m, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;

	return _get_debugfs_seq_nextx(pos);
}

static void _ge_debugfs_seq_stop(struct seq_file *m, void *v)
{
	/* do nothing */
}

static void *_ge_debugfs_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	*pos += 1;
	return _get_debugfs_seq_nextx(pos);
}

static int _ge_debugfs_seq_show(struct seq_file *m, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_printf(m, "max: %d\n", GE_POOL_ENTRY_SIZE);
	} else {
		GEEntry *entry;

		mutex_lock(&gPoolMutex);
		entry = *((GEEntry **)v);
		if (entry) {
			int i;
			int memory_size = 0;
			int memory_ksize = 0;
			int regions = 0;
			int idx = ((char *)v - (char *)&gPoolEntry[0]) /
					sizeof(GEEntry *);

			memory_size += (sizeof(uint32_t) + sizeof(uint32_t *)) *
					entry->region_num;
			memory_ksize += ksize(entry->data);
			for (i = 0; i < entry->region_num; ++i) {
				if (entry->region_data[i]) {
					regions |= (1 << i);
					memory_size += entry->region_sizes[i];
					memory_ksize +=
						ksize(entry->region_data[i]);
				}
			}

			seq_printf(m,
				"idx: %03x, ref: %d, region:%x data_size: (%d)%d bytes\n",
				idx, entry->ref, regions, memory_size,
				memory_ksize);
		}
		mutex_unlock(&gPoolMutex);
	}

	return 0;
}

static struct seq_operations gDEFEntryOps = {
	.start = _ge_debugfs_seq_start,
	.stop = _ge_debugfs_seq_stop,
	.next = _ge_debugfs_seq_next,
	.show = _ge_debugfs_seq_show,
};

static ssize_t _ge_debugfs_write_entry(const char __user *pszBuffer,
		size_t uiCount, loff_t uiPosition, void *pvData)
{
	return uiCount;
}

/*****************************************************************************
 *  init / exit
 *****************************************************************************/

int ged_ge_init(void)
{
	/*
	 * ABI lock-down. Every assertion below is a layout that was read out
	 * of the vendor libged.so with aarch64-linux-gnu-objdump -d, not
	 * inferred from how an MTK struct "usually" looks; the per-struct
	 * evidence is quoted at each definition in ged_bridge.h. If a later
	 * edit changes any of these, the build must break rather than ship a
	 * kernel that silently mis-parses what the blob sends.
	 */

	/* The package itself. ged_bridge_call@0x3f8c builds it on the stack at
	 * x29+48 and passes 'add x2, x29, #0x30': ui32FunctionID at +0
	 * ('str w1, [x29, #48]'), i32Size at +4 ('str w8, [x29, #52]' with
	 * w8 = #0x28), pvParamIn at +8, i32InBufferSize at +16, pvParamOut at
	 * +24, i32OutBufferSize at +32. w8 = 40 is also the _IOC_SIZE the
	 * blob encodes, so this size is doubly attested.
	 */
	BUILD_BUG_ON(sizeof(GED_BRIDGE_PACKAGE) != 40);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_PACKAGE, ui32FunctionID) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_PACKAGE, i32Size) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_PACKAGE, pvParamIn) != 8);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_PACKAGE, i32InBufferSize) != 16);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_PACKAGE, pvParamOut) != 24);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_PACKAGE, i32OutBufferSize) != 32);

	/* GED_ERROR is an enum; the blob reads every eError as a 32-bit word
	 * ('ldr w0, [x29, #64]' and friends), so it must stay int-sized.
	 */
	BUILD_BUG_ON(sizeof(GED_ERROR) != 4);

	/* The exact ioctl numbers observed on this device. They appear both in
	 * the blob ('mov w1, #0x6764'..'#0x6768' + 'movk w1, #0xc028, lsl 16')
	 * and in the live audit log: avc denied { ioctl } path="/proc/ged"
	 * ioctlcmd=6767 and ioctlcmd=6768
	 * [captures/m95-boot-20260807/m95-logcat-1821.txt].
	 */
	BUILD_BUG_ON(GED_BRIDGE_IO_GE_ALLOC   != 0xc0286764);
	BUILD_BUG_ON(GED_BRIDGE_IO_GE_RETAIN  != 0xc0286765);
	BUILD_BUG_ON(GED_BRIDGE_IO_GE_RELEASE != 0xc0286766);
	BUILD_BUG_ON(GED_BRIDGE_IO_GE_GET     != 0xc0286767);
	BUILD_BUG_ON(GED_BRIDGE_IO_GE_SET     != 0xc0286768);

	/* GE_ALLOC: in is 4 + 4*region_num, out is 8. */
	BUILD_BUG_ON(sizeof(GED_BRIDGE_IN_GE_ALLOC) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_ALLOC, region_num) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_ALLOC, region_sizes) != 4);
	BUILD_BUG_ON(sizeof(GED_BRIDGE_OUT_GE_ALLOC) != 8);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_ALLOC, ge_hnd) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_ALLOC, eError) != 4);

	/* GE_RETAIN / GE_RELEASE: in 4, out 8 with ref first. */
	BUILD_BUG_ON(sizeof(GED_BRIDGE_IN_GE_RETAIN) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_RETAIN, ge_hnd) != 0);
	BUILD_BUG_ON(sizeof(GED_BRIDGE_OUT_GE_RETAIN) != 8);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_RETAIN, ref) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_RETAIN, eError) != 4);
	BUILD_BUG_ON(sizeof(GED_BRIDGE_IN_GE_RELEASE) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_RELEASE, ge_hnd) != 0);
	BUILD_BUG_ON(sizeof(GED_BRIDGE_OUT_GE_RELEASE) != 8);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_RELEASE, ref) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_RELEASE, eError) != 4);

	/* GE_GET: in a fixed 16, out is eError then the payload at +4. */
	BUILD_BUG_ON(sizeof(GED_BRIDGE_IN_GE_GET) != 16);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_GET, ge_hnd) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_GET, region_id) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_GET, uint32_offset) != 8);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_GET, uint32_size) != 12);
	BUILD_BUG_ON(sizeof(GED_BRIDGE_OUT_GE_GET) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_GET, eError) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_GET, data) != 4);

	/* GE_SET: in is 16 + 4*uint32_size with the payload at +16, out 4. */
	BUILD_BUG_ON(sizeof(GED_BRIDGE_IN_GE_SET) != 16);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_SET, ge_hnd) != 0);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_SET, region_id) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_SET, uint32_offset) != 8);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_SET, uint32_size) != 12);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_IN_GE_SET, data) != 16);
	BUILD_BUG_ON(sizeof(GED_BRIDGE_OUT_GE_SET) != 4);
	BUILD_BUG_ON(offsetof(GED_BRIDGE_OUT_GE_SET, eError) != 0);

	/* The handle encoding must round-trip through the pool index. */
	BUILD_BUG_ON(GE_POOL_ENTRY_SIZE != (1 << GE_POOL_ENTRY_SHIFT));
	BUILD_BUG_ON(GE_MAX_REGION_NUM > GE_POOL_ENTRY_SIZE);

	gPoolCache = kmem_cache_create("gralloc_extra", sizeof(GEEntry), 0,
			0, NULL);
	if (!gPoolCache) {
		GE_PERR("fail to create gralloc_extra kmem_cache\n");
		return GED_ERROR_OOM;
	}

	ged_debugFS_create_entry(
			"ge",
			NULL,
			&gDEFEntryOps,
			_ge_debugfs_write_entry,
			NULL,
			&gDFSEntry);

	return GED_OK;
}

int ged_ge_exit(void)
{
	ged_debugFS_remove_entry(gDFSEntry);

	/* TODO : free all memory */
	if (gPoolCache) {
		kmem_cache_destroy(gPoolCache);
		gPoolCache = NULL;
	}

	return GED_OK;
}

/*****************************************************************************
 *  per-file context, so that a crashed client does not leak its entries
 *****************************************************************************/

void ged_ge_context_ref(GED_FILE_PRIVATE_BASE *base, uint32_t ge_hnd)
{
	GED_GE_FILE *file = container_of(base, GED_GE_FILE, base);
	int idx = GE_GEHND2IDX(ge_hnd);

	if (file) {
		mutex_lock(&gPoolMutex);
		file->ref_table[idx] += 1;
		mutex_unlock(&gPoolMutex);
	}
}

void ged_ge_context_deref(GED_FILE_PRIVATE_BASE *base, uint32_t ge_hnd)
{
	GED_GE_FILE *file;
	int idx = GE_GEHND2IDX(ge_hnd);

	if (!base)
		return;

	file = container_of(base, GED_GE_FILE, base);

	mutex_lock(&gPoolMutex);
	file->ref_table[idx] -= 1;
	mutex_unlock(&gPoolMutex);
}

static void _ged_ge_free_entry(GEEntry *entry)
{
	int i;

	GE_PERR("M95GE free ver=%d ref=%d pid=%d(%s)\n",
			entry->ver, entry->ref, current->pid, current->comm);

	for (i = 0; i < entry->region_num; ++i)
		kfree(entry->region_data[i]);
	kfree(entry->data);
	kmem_cache_free(gPoolCache, entry);
}

static void _ged_ge_deinit_context(void *base)
{
	int i;
	GED_GE_FILE *file = container_of(base, GED_GE_FILE, base);

	mutex_lock(&gPoolMutex);

	for (i = 0; i < GE_POOL_ENTRY_SIZE; ++i) {
		int deref = file->ref_table[i];
		GEEntry *entry = gPoolEntry[i];

		if (deref > 0 && entry) {
			entry->ref -= deref;

			if (entry->ref <= 0) {
				gPoolEntry[i] = NULL;
				_ged_ge_free_entry(entry);
			}
		}
	}

	mutex_unlock(&gPoolMutex);

	kfree(file);
}

int ged_ge_init_context(void **pbase)
{
	GED_FILE_PRIVATE_BASE *base = (GED_FILE_PRIVATE_BASE *)*pbase;

	if (!base) {
		GED_GE_FILE *file = kzalloc(sizeof(GED_GE_FILE), GFP_KERNEL);

		if (!file) {
			GE_PERR("fail to allocate GE_FILE: size:%zu\n",
					sizeof(GED_GE_FILE));
			return 1;
		}

		file->base.free_func = _ged_ge_deinit_context;

		*(GED_FILE_PRIVATE_BASE **)pbase = &file->base;
	} else if (base->free_func != _ged_ge_deinit_context) {
		/* Someone else owns private_data. GE is currently the only user,
		 * so this cannot happen; refuse rather than BUG() the device.
		 */
		GE_PERR("private is not used by GE, please check!!\n");
		return 1;
	}

	return 0;
}

/*****************************************************************************
 *  pool
 *****************************************************************************/

static int _get_unused_idx(void)
{
	int i;

	for (i = 0; i < GE_POOL_ENTRY_SIZE; ++i) {
		if (gPoolEntry[i] == NULL)
			return i;
	}

	return -1;
}

/* caller must hold gPoolMutex */
static GEEntry *_gehnd2entry(uint32_t ge_hnd)
{
	GEEntry *entry = NULL;
	uint32_t idx = GE_GEHND2IDX(ge_hnd);

	if (idx < GE_POOL_ENTRY_SIZE) {
		entry = gPoolEntry[idx];

		/* check ver, so a stale handle cannot address a recycled slot */
		if (entry && entry->ver != GE_GEHND2VER(ge_hnd))
			entry = NULL;
	}

	return entry;
}

uint32_t ged_ge_alloc(int region_num, uint32_t *region_sizes)
{
	int i;
	GEEntry *entry;
	int idx = -1;
	uint32_t ge_hnd = GE_INVALID_GEHND;
	size_t data_size;

	/* region_num comes straight from userspace and sizes a kmalloc. */
	if (region_num <= 0 || region_num > GE_MAX_REGION_NUM) {
		GE_PERR("invalid region_num: %d\n", region_num);
		return GE_INVALID_GEHND;
	}

	for (i = 0; i < region_num; ++i) {
		if (region_sizes[i] > GE_MAX_REGION_SIZE) {
			GE_PERR("invalid region_sizes[%d]: %u\n",
					i, region_sizes[i]);
			return GE_INVALID_GEHND;
		}
	}

	entry = (GEEntry *)kmem_cache_zalloc(gPoolCache, GFP_KERNEL);
	if (!entry) {
		GE_PERR("alloc entry fail, size:%zu\n", sizeof(GEEntry));
		goto err_entry;
	}

	entry->region_num = region_num;

	data_size = (sizeof(uint32_t) + sizeof(uint32_t *)) * region_num;
	entry->data = kzalloc(data_size, GFP_KERNEL);
	if (!entry->data) {
		GE_PERR("alloc data fail, size:%zu\n", data_size);
		goto err_kmalloc;
	}

	entry->region_sizes = (uint32_t *)entry->data;
	entry->region_data = (uint32_t **)((char *)entry->data +
			sizeof(uint32_t) * region_num);
	for (i = 0; i < region_num; ++i)
		entry->region_sizes[i] = region_sizes[i];

	mutex_lock(&gPoolMutex);

	idx = _get_unused_idx();
	if (idx < 0) {
		GE_PERR("pool full!!, PoolLimit: %d\n", GE_POOL_ENTRY_SIZE);
		mutex_unlock(&gPoolMutex);
		goto err_unused_idx;
	}

	entry->ref = 1;
	gPoolEntry[idx] = entry;

	/* gen ver for check, find a non-zero value */
	do {
		entry->ver = gver++;
	} while (entry->ver == 0);

	mutex_unlock(&gPoolMutex);

	/* encode a user_hnd */
	ge_hnd = (entry->ver << GE_POOL_ENTRY_SHIFT) | idx;

	/* M95GE: temporary lifecycle trace. Userspace was handing back handles we
	 * had already recycled (idx 0 at ver 1 and ver 3), so print who gets what
	 * and who later frees it. Remove once the ownership rule is settled.
	 */
	GE_PERR("M95GE alloc hnd=0x%x idx=%d ver=%d regions=%d pid=%d(%s)\n",
			ge_hnd, idx, entry->ver, region_num,
			current->pid, current->comm);

	return ge_hnd;

err_unused_idx:
	kfree(entry->data);
err_kmalloc:
	kmem_cache_free(gPoolCache, entry);
err_entry:
	return ge_hnd;
}

int32_t ged_ge_retain(uint32_t ge_hnd)
{
	int old_ref = -1;
	GEEntry *entry;

	mutex_lock(&gPoolMutex);

	entry = _gehnd2entry(ge_hnd);
	if (!entry) {
		GE_PERR("M95GE %s FAIL hnd=0x%x idx=%d ver=%d pid=%d(%s)\n", __func__, ge_hnd, GE_GEHND2IDX(ge_hnd), GE_GEHND2VER(ge_hnd), current->pid, current->comm);
		mutex_unlock(&gPoolMutex);
		return -1;
	}

	old_ref = entry->ref;
	entry->ref += 1;

	mutex_unlock(&gPoolMutex);

	return old_ref;
}

int32_t ged_ge_release(uint32_t ge_hnd)
{
	int old_ref = -1;
	GEEntry *entry;

	mutex_lock(&gPoolMutex);

	entry = _gehnd2entry(ge_hnd);
	if (!entry) {
		GE_PERR("M95GE %s FAIL hnd=0x%x idx=%d ver=%d pid=%d(%s)\n", __func__, ge_hnd, GE_GEHND2IDX(ge_hnd), GE_GEHND2VER(ge_hnd), current->pid, current->comm);
		mutex_unlock(&gPoolMutex);
		return -1;
	}

	old_ref = entry->ref;
	entry->ref -= 1;
	if (old_ref == 1) {
		/* remove from pool first */
		gPoolEntry[GE_GEHND2IDX(ge_hnd)] = NULL;
	}

	mutex_unlock(&gPoolMutex);

	if (old_ref == 1)
		_ged_ge_free_entry(entry);

	return old_ref;
}

/*
 * Validate a (region_id, u32_offset, u32_size) triple against an entry.
 * All three are userspace-controlled ints and are used to index a kmalloc'd
 * region; the upstream MediaTek code checks none of them, which is the
 * integer-overflow hole this driver is known for. Everything is done in
 * size_t after the negative values are rejected, so no product can wrap.
 *
 * Returns the region byte size on success, or a negative value.
 */
static int _ge_check_range(GEEntry *entry, int region_id, int u32_offset,
		int u32_size)
{
	size_t end;

	if (region_id < 0 || region_id >= entry->region_num)
		return -1;

	if (u32_offset < 0 || u32_size < 0)
		return -1;

	end = ((size_t)u32_offset + (size_t)u32_size) * sizeof(uint32_t);
	if (end > (size_t)entry->region_sizes[region_id])
		return -1;

	return 0;
}

int ged_ge_get(uint32_t ge_hnd, int region_id, int u32_offset, int u32_size,
		uint32_t *output_data)
{
	int i;
	GEEntry *entry;
	uint32_t *pregion_data;

	mutex_lock(&gPoolMutex);

	entry = _gehnd2entry(ge_hnd);
	if (!entry) {
		mutex_unlock(&gPoolMutex);
		GE_PERR("M95GE lookup FAIL hnd=0x%x idx=%d ver=%d pid=%d(%s)\n", ge_hnd, GE_GEHND2IDX(ge_hnd), GE_GEHND2VER(ge_hnd), current->pid, current->comm);
		return -1;
	}

	if (_ge_check_range(entry, region_id, u32_offset, u32_size) < 0) {
		mutex_unlock(&gPoolMutex);
		GE_PERR("out of range: hnd 0x%x region %d off %d size %d\n",
				ge_hnd, region_id, u32_offset, u32_size);
		return -1;
	}

	/* An unwritten region reads back as zeroes; ged_ge_set allocates it
	 * lazily, and gralloc legitimately queries before it ever sets.
	 */
	pregion_data = entry->region_data[region_id];
	if (pregion_data) {
		for (i = 0; i < u32_size; ++i)
			output_data[i] = pregion_data[u32_offset + i];
	} else {
		for (i = 0; i < u32_size; ++i)
			output_data[i] = 0;
	}

	mutex_unlock(&gPoolMutex);

	return 0;
}

int ged_ge_set(uint32_t ge_hnd, int region_id, int u32_offset, int u32_size,
		uint32_t *input_data)
{
	int i;
	GEEntry *entry;
	uint32_t *pregion_data;

	mutex_lock(&gPoolMutex);

	entry = _gehnd2entry(ge_hnd);
	if (!entry) {
		mutex_unlock(&gPoolMutex);
		GE_PERR("M95GE lookup FAIL hnd=0x%x idx=%d ver=%d pid=%d(%s)\n", ge_hnd, GE_GEHND2IDX(ge_hnd), GE_GEHND2VER(ge_hnd), current->pid, current->comm);
		return -1;
	}

	if (_ge_check_range(entry, region_id, u32_offset, u32_size) < 0) {
		mutex_unlock(&gPoolMutex);
		GE_PERR("out of range: hnd 0x%x region %d off %d size %d\n",
				ge_hnd, region_id, u32_offset, u32_size);
		return -1;
	}

	if (!entry->region_data[region_id]) {
		/* lazy allocate */
		entry->region_data[region_id] =
			kzalloc(entry->region_sizes[region_id], GFP_KERNEL);
		if (!entry->region_data[region_id]) {
			mutex_unlock(&gPoolMutex);
			GE_PERR("alloc region fail, size:%u\n",
					entry->region_sizes[region_id]);
			return -1;
		}
	}

	pregion_data = entry->region_data[region_id];
	for (i = 0; i < u32_size; ++i)
		pregion_data[u32_offset + i] = input_data[i];

	mutex_unlock(&gPoolMutex);

	return 0;
}

/*****************************************************************************
 *  bridge entry points
 *****************************************************************************/

int ged_bridge_ge_alloc(GED_BRIDGE_IN_GE_ALLOC *psALLOC_IN,
		GED_BRIDGE_OUT_GE_ALLOC *psALLOC_OUT)
{
	psALLOC_OUT->ge_hnd = ged_ge_alloc(psALLOC_IN->region_num,
			psALLOC_IN->region_sizes);
	psALLOC_OUT->eError = (psALLOC_OUT->ge_hnd != GE_INVALID_GEHND) ?
			GED_OK : GED_ERROR_OOM;
	return 0;
}

int ged_bridge_ge_retain(GED_BRIDGE_IN_GE_RETAIN *psRETAIN_IN,
		GED_BRIDGE_OUT_GE_RETAIN *psRETAIN_OUT)
{
	psRETAIN_OUT->ref = ged_ge_retain(psRETAIN_IN->ge_hnd);
	psRETAIN_OUT->eError = (psRETAIN_OUT->ref >= 0) ?
			GED_OK : GED_ERROR_INVALID_PARAMS;
	return 0;
}

int ged_bridge_ge_release(GED_BRIDGE_IN_GE_RELEASE *psRELEASE_IN,
		GED_BRIDGE_OUT_GE_RELEASE *psRELEASE_OUT)
{
	psRELEASE_OUT->ref = ged_ge_release(psRELEASE_IN->ge_hnd);
	psRELEASE_OUT->eError = (psRELEASE_OUT->ref >= 0) ?
			GED_OK : GED_ERROR_INVALID_PARAMS;
	return 0;
}

int ged_bridge_ge_get(GED_BRIDGE_IN_GE_GET *psGET_IN,
		GED_BRIDGE_OUT_GE_GET *psGET_OUT)
{
	psGET_OUT->eError = ged_ge_get(
			psGET_IN->ge_hnd,
			psGET_IN->region_id,
			psGET_IN->uint32_offset,
			psGET_IN->uint32_size,
			psGET_OUT->data) ?
		GED_ERROR_INVALID_PARAMS : GED_OK;
	return 0;
}

int ged_bridge_ge_set(GED_BRIDGE_IN_GE_SET *psSET_IN,
		GED_BRIDGE_OUT_GE_SET *psSET_OUT)
{
	psSET_OUT->eError = ged_ge_set(
			psSET_IN->ge_hnd,
			psSET_IN->region_id,
			psSET_IN->uint32_offset,
			psSET_IN->uint32_size,
			psSET_IN->data) ?
		GED_ERROR_INVALID_PARAMS : GED_OK;
	return 0;
}
