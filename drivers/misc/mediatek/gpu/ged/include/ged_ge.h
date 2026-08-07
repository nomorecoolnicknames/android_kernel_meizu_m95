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

#ifndef __GED_GE_H__
#define __GED_GE_H__

#include <linux/types.h>

#include "ged_type.h"

/*
 * "GE" is gralloc_extra: a per-graphic-buffer side-band metadata store that
 * lives in the GED driver. gralloc.mt6797.so keeps a GE handle inside every
 * buffer_handle_t and uses it for every attribute the Mali gralloc does not
 * implement itself.
 *
 * The m685 BSP drop of ged/ predates this feature - its bridge enum stops at
 * GED_BRIDGE_COMMAND_EVENT_NOTIFY (9) - but the Flyme vendor blobs are built
 * against a BSP that has it, so they issue bridge IDs 100..104 that this
 * kernel answered with "Unknown Bridge ID" / -EFAULT. This header and
 * ged_ge.c restore that ABI. See the BUILD_BUG_ON block in ged_ge_init() for
 * the layout assertions recovered from the blobs.
 */

#define GE_POOL_ENTRY_SHIFT	(10)
#define GE_POOL_ENTRY_SIZE	(1 << GE_POOL_ENTRY_SHIFT)
#define GE_INVALID_GEHND	0
#define GE_GEHND2IDX(gehnd)	((gehnd) & (GE_POOL_ENTRY_SIZE - 1))
#define GE_GEHND2VER(gehnd)	((gehnd) >> GE_POOL_ENTRY_SHIFT)

/* Sanity bounds. The reference implementation has none, which is what made
 * the MediaTek GED integer-overflow class of bugs possible: region_num and
 * u32_offset/u32_size come straight from userspace and are used to size a
 * kmalloc and to index it. Cap them at values far above anything gralloc
 * asks for (observed: region_num 2, region sizes a few hundred bytes).
 */
#define GE_MAX_REGION_NUM	16
#define GE_MAX_REGION_SIZE	(64 * 1024)

int ged_ge_init(void);
int ged_ge_exit(void);

int ged_ge_init_context(void **pp_priv);

void ged_ge_context_ref(GED_FILE_PRIVATE_BASE *base, uint32_t ge_hnd);
void ged_ge_context_deref(GED_FILE_PRIVATE_BASE *base, uint32_t ge_hnd);

uint32_t ged_ge_alloc(int region_num, uint32_t *region_sizes);
int32_t ged_ge_retain(uint32_t ge_hnd);
int32_t ged_ge_release(uint32_t ge_hnd);

int ged_ge_get(uint32_t ge_hnd, int region_id, int u32_offset, int u32_size,
		uint32_t *output_data);
int ged_ge_set(uint32_t ge_hnd, int region_id, int u32_offset, int u32_size,
		uint32_t *input_data);

#endif
