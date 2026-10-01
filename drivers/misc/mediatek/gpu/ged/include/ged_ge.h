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
 * The base BSP predates this feature, while the vendor userspace issues
 * bridge IDs 100..104. See the BUILD_BUG_ON block in ged_ge_init() for the
 * layout assertions.
 */

#define GE_POOL_ENTRY_SHIFT	(10)
#define GE_POOL_ENTRY_SIZE	(1 << GE_POOL_ENTRY_SHIFT)
#define GE_INVALID_GEHND	0
#define GE_GEHND2IDX(gehnd)	((gehnd) & (GE_POOL_ENTRY_SIZE - 1))
#define GE_GEHND2VER(gehnd)	((gehnd) >> GE_POOL_ENTRY_SHIFT)

/* Sanity bounds: region_num and u32_offset/u32_size come straight from
 * userspace and size and index a kmalloc. The caps are far above what
 * gralloc uses.
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
