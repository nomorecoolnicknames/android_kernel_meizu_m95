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

#ifndef __GED_BRIDGE_H__
#define __GED_BRIDGE_H__

/* GED_IO/GED_IOW/GED_IOR/GED_IOWR below expand to _IO*(), so this header needs
 * <linux/ioctl.h> to stand on its own. It never did; every pre-existing
 * includer happened to pull the definitions in transitively, and the omission
 * only surfaced when ged_ge.c started using the macros directly
 * ("error: implicit declaration of function '_IOWR'"). Include it here rather
 * than papering over it at each call site.
 */
#include <linux/ioctl.h>

#include "ged_base.h"
#include "ged_log.h"
#include "ged_type.h"


typedef struct _GED_BRIDGE_PACKAGE
{
    unsigned int    ui32FunctionID;
    int             i32Size;
    void            *pvParamIn;
    int             i32InBufferSize;
    void            *pvParamOut;
    int             i32OutBufferSize;
} GED_BRIDGE_PACKAGE;

/*****************************************************************************
 *  IOCTL values.
 *****************************************************************************/

#define GED_MAGIC 'g'

#define GED_IO(INDEX)    _IO(GED_MAGIC, INDEX, GED_BRIDGE_PACKAGE)
#define GED_IOW(INDEX)   _IOW(GED_MAGIC, INDEX, GED_BRIDGE_PACKAGE)
#define GED_IOR(INDEX)   _IOR(GED_MAGIC, INDEX, GED_BRIDGE_PACKAGE)
#define GED_IOWR(INDEX)  _IOWR(GED_MAGIC, INDEX, GED_BRIDGE_PACKAGE)
#define GED_GET_BRIDGE_ID(X)	_IOC_NR(X)

/******************************************************************************
 *  IOCTL Commands
 ******************************************************************************/
typedef enum
{
    GED_BRIDGE_COMMAND_LOG_BUF_GET,
    GED_BRIDGE_COMMAND_LOG_BUF_WRITE,
    GED_BRIDGE_COMMAND_LOG_BUF_RESET,
    GED_BRIDGE_COMMAND_BOOST_GPU_FREQ,
    GED_BRIDGE_COMMAND_MONITOR_3D_FENCE,
    GED_BRIDGE_COMMAND_QUERY_INFO,
    GED_BRIDGE_COMMAND_NOTIFY_VSYNC,
    GED_BRIDGE_COMMAND_DVFS_PROBE,
    GED_BRIDGE_COMMAND_DVFS_UM_RETURN,
	GED_BRIDGE_COMMAND_EVENT_NOTIFY,

	/*
	 * gralloc_extra ("GE"). Numbered from 100 by MediaTek so that the
	 * older block above stays stable; the value is load-bearing because
	 * it is the _IOC_NR the vendor blobs send. libged.so issues exactly
	 * 0xC0286764..0xC0286768 - see the BUILD_BUG_ON block in
	 * ged_ge_init() and the disassembly note there.
	 */
	GED_BRIDGE_COMMAND_GE_ALLOC = 100,
	GED_BRIDGE_COMMAND_GE_RETAIN,
	GED_BRIDGE_COMMAND_GE_RELEASE,
	GED_BRIDGE_COMMAND_GE_GET,
	GED_BRIDGE_COMMAND_GE_SET,
} GED_BRIDGE_COMMAND_ID;

#define GED_BRIDGE_IO_LOG_BUF_GET			GED_IOWR(GED_BRIDGE_COMMAND_LOG_BUF_GET)
#define GED_BRIDGE_IO_LOG_BUF_WRITE			GED_IOWR(GED_BRIDGE_COMMAND_LOG_BUF_WRITE)
#define GED_BRIDGE_IO_LOG_BUF_RESET			GED_IOWR(GED_BRIDGE_COMMAND_LOG_BUF_RESET)
#define GED_BRIDGE_IO_BOOST_GPU_FREQ		GED_IOWR(GED_BRIDGE_COMMAND_BOOST_GPU_FREQ)
#define GED_BRIDGE_IO_MONITOR_3D_FENCE      GED_IOWR(GED_BRIDGE_COMMAND_MONITOR_3D_FENCE)
#define GED_BRIDGE_IO_QUERY_INFO      GED_IOWR(GED_BRIDGE_COMMAND_QUERY_INFO)
#define GED_BRIDGE_IO_NOTIFY_VSYNC       GED_IOWR(GED_BRIDGE_COMMAND_NOTIFY_VSYNC)
#define GED_BRIDGE_IO_DVFS_PROBE       GED_IOWR(GED_BRIDGE_COMMAND_DVFS_PROBE)
#define GED_BRIDGE_IO_DVFS_UM_RETURN GED_IOWR(GED_BRIDGE_COMMAND_DVFS_UM_RETURN)
#define GED_BRIDGE_IO_EVENT_NOTIFY GED_IOWR(GED_BRIDGE_COMMAND_EVENT_NOTIFY)

#define GED_BRIDGE_IO_GE_ALLOC		GED_IOWR(GED_BRIDGE_COMMAND_GE_ALLOC)
#define GED_BRIDGE_IO_GE_RETAIN		GED_IOWR(GED_BRIDGE_COMMAND_GE_RETAIN)
#define GED_BRIDGE_IO_GE_RELEASE	GED_IOWR(GED_BRIDGE_COMMAND_GE_RELEASE)
#define GED_BRIDGE_IO_GE_GET		GED_IOWR(GED_BRIDGE_COMMAND_GE_GET)
#define GED_BRIDGE_IO_GE_SET		GED_IOWR(GED_BRIDGE_COMMAND_GE_SET)

/*****************************************************************************
 *  LOG_BUF_GET
 *****************************************************************************/
    
/* Bridge in structure for LOG_BUF_GET */
typedef struct GED_BRIDGE_IN_LOGBUFGET_TAG
{
    char acName[GED_LOG_BUF_NAME_LENGTH];
} GED_BRIDGE_IN_LOGBUFGET;


/* Bridge out structure for LOG_BUF_GETC */
typedef struct GED_BRIDGE_OUT_LOGBUFGET_TAG
{
    GED_ERROR eError;
    GED_LOG_BUF_HANDLE hLogBuf;
} GED_BRIDGE_OUT_LOGBUFGET;

/*****************************************************************************
 *  LOG_BUF_WRITE
 *****************************************************************************/

#define GED_BRIDGE_IN_LOGBUF_SIZE 320

/* Bridge in structure for LOG_BUF_WRITE */
typedef struct GED_BRIDGE_IN_LOGBUFWRITE_TAG
{
    GED_LOG_BUF_HANDLE hLogBuf;
    int attrs;
    char acLogBuf[GED_BRIDGE_IN_LOGBUF_SIZE];
} GED_BRIDGE_IN_LOGBUFWRITE;

/* Bridge out structure for LOG_BUF_WRITE */
typedef struct GED_BRIDGE_OUT_LOGBUFWRITE_TAG
{
    GED_ERROR eError;
} GED_BRIDGE_OUT_LOGBUFWRITE;

/******************************************************************************
 *  LOG_BUF_RESET
 ******************************************************************************/

/* Bridge in structure for LOG_BUF_RESET */
typedef struct GED_BRIDGE_IN_LOGBUFRESET_TAG
{
    GED_LOG_BUF_HANDLE hLogBuf;
} GED_BRIDGE_IN_LOGBUFRESET;

/* Bridge out structure for LOG_BUF_RESET */
typedef struct GED_BRIDGE_OUT_LOGBUFRESET_TAG
{
    GED_ERROR eError;
} GED_BRIDGE_OUT_LOGBUFRESET;

/*****************************************************************************
 *  BOOST GPU FREQ
 *****************************************************************************/

typedef enum
{
    GED_BOOST_GPU_FREQ_LEVEL_MAX = 100
} GED_BOOST_GPU_FREQ_LEVEL;

/* Bridge in structure for LOG_BUF_WRITE */
typedef struct GED_BRIDGE_IN_BOOSTGPUFREQ_TAG
{
    GED_BOOST_GPU_FREQ_LEVEL eGPUFreqLevel;
} GED_BRIDGE_IN_BOOSTGPUFREQ;

/* Bridge out structure for LOG_BUF_WRITE */
typedef struct GED_BRIDGE_OUT_BOOSTGPUFREQ_TAG
{
    GED_ERROR eError;
} GED_BRIDGE_OUT_BOOSTGPUFREQ;

/*****************************************************************************
 *  MONITOR 3D FENCE
 *****************************************************************************/

/* Bridge in structure for MONITOR3DFENCE */
typedef struct GED_BRIDGE_IN_MONITOR3DFENCE_TAG
{
    int fd;
} GED_BRIDGE_IN_MONITOR3DFENCE;

/* Bridge out structure for MONITOR3DFENCE */
typedef struct GED_BRIDGE_OUT_MONITOR3DFENCE_TAG
{
    GED_ERROR eError;
} GED_BRIDGE_OUT_MONITOR3DFENCE;

/*****************************************************************************
 *  QUERY INFO
 *****************************************************************************/

/* Bridge in structure for QUERY INFO*/
typedef struct GED_BRIDGE_IN_QUERY_INFO_TAG
{
    GED_INFO eType;
} GED_BRIDGE_IN_QUERY_INFO;


/* Bridge out structure for QUERY INFO*/
typedef struct GED_BRIDGE_OUT_QUERY_INFO_TAG
{
    unsigned long   retrieve;
} GED_BRIDGE_OUT_QUERY_INFO;
/*****************************************************************************
 *  NOTIFY VSYNC
 *****************************************************************************/

/* Bridge in structure for VSYNCEVENT */
typedef struct GED_BRIDGE_IN_NOTIFY_VSYNC_TAG
{
    GED_VSYNC_TYPE eType;
} GED_BRIDGE_IN_NOTIFY_VSYNC;

/* Bridge out structure for VSYNCEVENT */
typedef struct GED_BRIDGE_OUT_NOTIFY_VSYNC_TAG
{
    GED_DVFS_UM_QUERY_PACK sQueryData;
    GED_ERROR eError;
} GED_BRIDGE_OUT_NOTIFY_VSYNC;

/*****************************************************************************
 *  DVFS PROBE
 *****************************************************************************/

/* Bridge in structure for SWVSYNCEVENT */
typedef struct GED_BRIDGE_IN_DVFS_PROBE_TAG
{
    int          pid;
} GED_BRIDGE_IN_DVFS_PROBE;

/* Bridge out structure for RECORDSWAPBUFFERS */
typedef struct GED_BRIDGE_OUT_DVFS_PROBE_TAG
{
    GED_ERROR eError;
} GED_BRIDGE_OUT_DVFS_PROBE;

/*****************************************************************************
 *  DVFS UM RETURN
 *****************************************************************************/

/* Bridge in structure for DVFS_UM_RETURN */
typedef struct GED_BRIDGE_IN_DVFS_UM_RETURN_TAG
{
   unsigned long gpu_tar_freq; 
   bool bFallback;
} GED_BRIDGE_IN_DVFS_UM_RETURN;

/* Bridge out structure for DVFS_UM_RETURN */
typedef struct GED_BRIDGE_OUT_DVFS_UM_RETURN_TAG
{
    GED_ERROR eError;
} GED_BRIDGE_OUT_DVFS_UM_RETURN;

/*****************************************************************************
 *  EVENT NOTIFY
 *****************************************************************************/

/* Bridge in structure for EVENT_NOTIFY */
typedef struct GED_BRIDGE_IN_EVENT_NOTIFY_TAG
{
   GED_DVFS_VSYNC_OFFSET_SWITCH_CMD eEvent; 
   bool bSwitch;
} GED_BRIDGE_IN_EVENT_NOTIFY;

/* Bridge out structure for EVENT_NOTIFY */
typedef struct GED_BRIDGE_OUT_EVENT_NOTIFY_TAG
{
    GED_ERROR eError;
} GED_BRIDGE_OUT_EVENT_NOTIFY;

/*****************************************************************************
 *  GRALLOC_EXTRA (GE)
 *
 *  Every layout below was recovered by disassembling the vendor
 *  libged.so (vendor/lib64/libged.so, the aarch64 build), not assumed. The
 *  register-level evidence is quoted per struct; ged_ge_init() turns all of
 *  it into BUILD_BUG_ON assertions so a later edit cannot silently drift.
 *
 *  ged_bridge_call(w0=fd, w1=ioctl_cmd, x2=pvParamIn, w3=inSize,
 *                  x4=pvParamOut, w5=outSize)
 *****************************************************************************/

/* Bridge in structure for GE_ALLOC
 *
 * ged_ge_alloc@0x4478: 'lsl w3, w19, #2' then 'add w1, w3, #0x4' builds the
 * in-size as 4 + 4*region_num, and 'str w19, [x0]' puts region_num at
 * offset 0 with the region_sizes[] array immediately after it.
 */
typedef struct GED_BRIDGE_IN_GE_ALLOC_TAG {
	int region_num;
	uint32_t region_sizes[0];
} GED_BRIDGE_IN_GE_ALLOC;

/* Bridge out structure for GE_ALLOC
 *
 * ged_ge_alloc@0x4570: 'mov w5, #0x8' is the out-size, and @0x4584
 * 'ldr w0, [x29, #64]' reads the returned handle from offset 0 of that
 * 8-byte buffer, leaving eError at offset 4.
 */
typedef struct GED_BRIDGE_OUT_GE_ALLOC_TAG {
	uint32_t ge_hnd;
	GED_ERROR eError;
} GED_BRIDGE_OUT_GE_ALLOC;

/* Bridge in structure for GE_RETAIN
 *
 * ged_ge_retain@0x4638: 'mov w3, #0x4' in-size, and @0x4644
 * 'str w21, [x2, #-24]!' stores the handle as the only member.
 */
typedef struct GED_BRIDGE_IN_GE_RETAIN_TAG {
	uint32_t ge_hnd;
} GED_BRIDGE_IN_GE_RETAIN;

/* Bridge out structure for GE_RETAIN
 *
 * ged_ge_retain@0x4640: 'mov w5, #0x8' out-size; @0x4650
 * 'ldr w0, [x29, #64]' reads ref from offset 0, eError follows at 4.
 */
typedef struct GED_BRIDGE_OUT_GE_RETAIN_TAG {
	int32_t ref;
	GED_ERROR eError;
} GED_BRIDGE_OUT_GE_RETAIN;

/* Bridge in structure for GE_RELEASE - ged_ge_release@0x46e8, identical
 * shape to GE_RETAIN ('mov w3, #0x4', 'str w4, [x2, #-24]!').
 */
typedef struct GED_BRIDGE_IN_GE_RELEASE_TAG {
	uint32_t ge_hnd;
} GED_BRIDGE_IN_GE_RELEASE;

/* Bridge out structure for GE_RELEASE - ged_ge_release@0x46f4
 * 'mov w5, #0x8'; @0x4708 'ldr w3, [x29, #48]' reads ref from offset 0.
 */
typedef struct GED_BRIDGE_OUT_GE_RELEASE_TAG {
	int32_t ref;
	GED_ERROR eError;
} GED_BRIDGE_OUT_GE_RELEASE;

/* Bridge in structure for GE_GET
 *
 * ged_ge_get@0x47d4: 'mov w3, #0x10' - the in-size is a fixed 16 bytes, and
 * @0x47e4..0x47f0 stores the four arguments consecutively at x29+120,
 * +124, +128, +132 (ge_hnd, region_id, uint32_offset, uint32_size) with
 * x2 = x29+0x78 = x29+120 as the buffer base, i.e. offsets 0/4/8/12.
 */
typedef struct GED_BRIDGE_IN_GE_GET_TAG {
	uint32_t ge_hnd;
	int region_id;
	int uint32_offset;
	int uint32_size;
} GED_BRIDGE_IN_GE_GET;

/* Bridge out structure for GE_GET
 *
 * ged_ge_get@0x47f8..0x480c: 'add x1, x20, #0x4' then
 * memcpy(caller_buf, x20+4, uint32_size*4) and 'ldr w25, [x20]' - so
 * eError sits at offset 0 and the payload starts at offset 4.
 *
 * Note the blob sizes this buffer as 16 + 4*uint32_size (@0x47b4
 * 'add w3, w5, #0x10'), 12 bytes more than it reads back. Harmless
 * over-allocation on its side; the kernel must not rely on the surplus.
 */
typedef struct GED_BRIDGE_OUT_GE_GET_TAG {
	GED_ERROR eError;
	uint32_t data[0];
} GED_BRIDGE_OUT_GE_GET;

/* Bridge in structure for GE_SET
 *
 * ged_ge_set@0x48f4..0x4904 stores ge_hnd at [x19], region_id at [x19,#4],
 * uint32_offset at [x19,#8], uint32_size at [x19,#12] and then
 * memcpy(x19+16, payload, uint32_size*4); the in-size @0x48c8
 * 'add w21, w21, #0x10' is 16 + 4*uint32_size.
 */
typedef struct GED_BRIDGE_IN_GE_SET_TAG {
	uint32_t ge_hnd;
	int region_id;
	int uint32_offset;
	int uint32_size;
	uint32_t data[0];
} GED_BRIDGE_IN_GE_SET;

/* Bridge out structure for GE_SET
 *
 * ged_ge_set@0x490c: 'mov w5, #0x4' out-size; @0x4934
 * 'ldr w5, [x29, #96]' reads eError from offset 0.
 */
typedef struct GED_BRIDGE_OUT_GE_SET_TAG {
	GED_ERROR eError;
} GED_BRIDGE_OUT_GE_SET;

/*****************************************************************************
 *  BRIDGE FUNCTIONS
 *****************************************************************************/

int ged_bridge_log_buf_get(
    GED_BRIDGE_IN_LOGBUFGET *psLogBufGetIN,
    GED_BRIDGE_OUT_LOGBUFGET *psLogBufGetOUT);

int ged_bridge_log_buf_write(
    GED_BRIDGE_IN_LOGBUFWRITE *psLogBufWriteIN,
    GED_BRIDGE_OUT_LOGBUFWRITE *psLogBufWriteOUT);

int ged_bridge_log_buf_reset(
    GED_BRIDGE_IN_LOGBUFRESET *psLogBufResetIn,
    GED_BRIDGE_OUT_LOGBUFRESET *psLogBufResetOUT);

int ged_bridge_boost_gpu_freq(
    GED_BRIDGE_IN_BOOSTGPUFREQ *psBoostGpuFreqIN,
    GED_BRIDGE_OUT_BOOSTGPUFREQ *psBoostGpuFreqOUT);

int ged_bridge_monitor_3D_fence(
    GED_BRIDGE_IN_MONITOR3DFENCE *psMonitor3DFenceINT,
    GED_BRIDGE_OUT_MONITOR3DFENCE *psMonitor3DFenceOUT);

int ged_bridge_query_info(
    GED_BRIDGE_IN_QUERY_INFO *psQueryInfoINT,
    GED_BRIDGE_OUT_QUERY_INFO *psQueryInfoOUT);

int ged_bridge_notify_vsync(
    GED_BRIDGE_IN_NOTIFY_VSYNC *psNotifyVsyncINT,
    GED_BRIDGE_OUT_NOTIFY_VSYNC *psNotifyVsyncOUT);

int ged_bridge_dvfs_probe(
    GED_BRIDGE_IN_DVFS_PROBE *psDVFSProbeINT, 
    GED_BRIDGE_OUT_DVFS_PROBE *psDVFSProbeOUT);

int ged_bridge_dvfs_um_retrun(
    GED_BRIDGE_IN_DVFS_UM_RETURN *psDVFS_UM_returnINT, 
    GED_BRIDGE_OUT_DVFS_UM_RETURN *psDVFS_UM_returnOUT);

int ged_bridge_event_notify(
		GED_BRIDGE_IN_EVENT_NOTIFY *psEVENT_NOTIFYINT,
		GED_BRIDGE_OUT_EVENT_NOTIFY *psEVENT_NOTIFYOUT);

int ged_bridge_ge_alloc(
	GED_BRIDGE_IN_GE_ALLOC *psALLOC_IN,
	GED_BRIDGE_OUT_GE_ALLOC *psALLOC_OUT);

int ged_bridge_ge_retain(
	GED_BRIDGE_IN_GE_RETAIN *psRETAIN_IN,
	GED_BRIDGE_OUT_GE_RETAIN *psRETAIN_OUT);

int ged_bridge_ge_release(
	GED_BRIDGE_IN_GE_RELEASE *psRELEASE_IN,
	GED_BRIDGE_OUT_GE_RELEASE *psRELEASE_OUT);

int ged_bridge_ge_get(
	GED_BRIDGE_IN_GE_GET *psGET_IN,
	GED_BRIDGE_OUT_GE_GET *psGET_OUT);

int ged_bridge_ge_set(
	GED_BRIDGE_IN_GE_SET *psSET_IN,
	GED_BRIDGE_OUT_GE_SET *psSET_OUT);

#endif
