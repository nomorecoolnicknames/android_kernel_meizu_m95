/*
* Copyright (C) 2011-2014 MediaTek Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _MTK_LINUX_ION_H
#define _MTK_LINUX_ION_H
enum mtk_ion_heap_type {
	ION_HEAP_TYPE_MULTIMEDIA = 10,
	ION_HEAP_TYPE_FB = 11,
	/*
	 * m95 bring-up: the Flyme mt6797 camera blobs allocate every camera
	 * image buffer through libion_mtk ion_alloc_camera(), which passes
	 * heap mask 0x1000 = 1 << 12 (disassembly of vendor
	 * lib/libion_mtk.so, ion_alloc_camera@0xc24: movw r3,#4096).
	 * The stock 3.18.41 Flyme kernel registers an MM-type heap under
	 * this id (ION_HEAP_TYPE_MULTIMEDIA_FOR_CAMERA in later MTK BSPs);
	 * this 3.18.22 drop predates it, so every camera alloc returned
	 * -ENODEV and hal3a NULL-crashed on teardown.
	 */
	ION_HEAP_TYPE_MULTIMEDIA_FOR_CAMERA = 12,
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
};
#define ION_HEAP_MULTIMEDIA_MASK (1 << ION_HEAP_TYPE_MULTIMEDIA)
#define ION_HEAP_FB_MASK         (1 << ION_HEAP_TYPE_FB)
#define ION_HEAP_CAMERA_MASK     (1 << ION_HEAP_TYPE_MULTIMEDIA_FOR_CAMERA)

#define ION_NUM_HEAP_IDS (sizeof(unsigned int) * 8)
#endif
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
