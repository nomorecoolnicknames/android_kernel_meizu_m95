/*
 * AK7371AF voice coil motor driver
 *
 *
 */

#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/module.h>

#include "lens_info.h"


#define AF_DRVNAME "AK7371AF_DRV"
#define AF_I2C_SLAVE_ADDR        0x18

#define AF_DEBUG
#ifdef AF_DEBUG
#define LOG_INF(format, args...) pr_debug(AF_DRVNAME " [%s] " format, __func__, ##args)
#else
#define LOG_INF(format, args...)
#endif


static struct i2c_client *g_pstAF_I2Cclient;
static int *g_pAF_Opened;
static spinlock_t *g_pAF_SpinLock;


static unsigned long g_u4AF_INF;
static unsigned long g_u4AF_MACRO = 1023;
static unsigned long g_u4TargetPosition;
static unsigned long g_u4CurrPosition;


static int s4AF_ReadReg(u8 a_uAddr, u16 *a_pu2Result)
{
	int i4RetValue = 0;
	char pBuff;
	char puSendCmd[1];

	puSendCmd[0] = a_uAddr;

	g_pstAF_I2Cclient->addr = AF_I2C_SLAVE_ADDR;

	g_pstAF_I2Cclient->addr = g_pstAF_I2Cclient->addr >> 1;

	i4RetValue = i2c_master_send(g_pstAF_I2Cclient, puSendCmd, 1);

	if (i4RetValue < 0) {
		LOG_INF("I2C read - send failed!!\n");
		return -1;
	}

	i4RetValue = i2c_master_recv(g_pstAF_I2Cclient, &pBuff, 1);

	if (i4RetValue < 0) {
		LOG_INF("I2C read - recv failed!!\n");
		return -1;
	}
	*a_pu2Result = pBuff;

	return 0;
}

static int s4AF_WriteReg(u16 a_u2Addr, u16 a_u2Data)
{
	int i4RetValue = 0;

	char puSendCmd[2] = { (char)a_u2Addr, (char)a_u2Data };

	g_pstAF_I2Cclient->addr = AF_I2C_SLAVE_ADDR;

	g_pstAF_I2Cclient->addr = g_pstAF_I2Cclient->addr >> 1;

	i4RetValue = i2c_master_send(g_pstAF_I2Cclient, puSendCmd, 2);

	if (i4RetValue < 0) {
		LOG_INF("I2C write failed!!\n");
		return -1;
	}

	return 0;
}

static inline int getAFInfo(__user stAF_MotorInfo * pstMotorInfo)
{
	stAF_MotorInfo stMotorInfo;

	stMotorInfo.u4MacroPosition = g_u4AF_MACRO;
	stMotorInfo.u4InfPosition = g_u4AF_INF;
	stMotorInfo.u4CurrentPosition = g_u4CurrPosition;
	stMotorInfo.bIsSupportSR = 1;

	stMotorInfo.bIsMotorMoving = 1;

	if (*g_pAF_Opened >= 1)
		stMotorInfo.bIsMotorOpen = 1;
	else
		stMotorInfo.bIsMotorOpen = 0;

	if (copy_to_user(pstMotorInfo, &stMotorInfo, sizeof(stAF_MotorInfo)))
		LOG_INF("copy to user failed when getting motor information\n");

	return 0;
}

static inline int setVCMPos(unsigned long a_u4Position)
{
	int i4RetValue = 0;

	i4RetValue = s4AF_WriteReg(0x0, (u16) ((a_u4Position >> 2) & 0xff));

	if (i4RetValue < 0)
		return -1;

	i4RetValue = s4AF_WriteReg(0x1, (u16) ((g_u4TargetPosition & 0x3) << 6));

	return i4RetValue;
}

static inline int moveAF(unsigned long a_u4Position)
{
	int ret = 0;

	if ((a_u4Position > g_u4AF_MACRO) || (a_u4Position < g_u4AF_INF)) {
		LOG_INF("out of range\n");
		return -EINVAL;
	}

	if (*g_pAF_Opened == 1) {
		unsigned short InitPos, InitPosM, InitPosL;

		/* 00:active mode        10:Standby mode    x1:Sleep mode */
		s4AF_WriteReg(0x02, 0x00);	/* from Standby mode to Active mode */
		msleep(20);
		s4AF_ReadReg(0x0, &InitPosM);
		ret = s4AF_ReadReg(0x1, &InitPosL);
		InitPos = ((InitPosM & 0xFF) << 2) + ((InitPosL >> 6) & 0x3);

		if (ret == 0) {
			LOG_INF("Init Pos %6d\n", InitPos);

			spin_lock(g_pAF_SpinLock);
			g_u4CurrPosition = (unsigned long)InitPos;
			spin_unlock(g_pAF_SpinLock);

		} else {
			spin_lock(g_pAF_SpinLock);
			g_u4CurrPosition = 0;
			spin_unlock(g_pAF_SpinLock);
		}

		spin_lock(g_pAF_SpinLock);
		*g_pAF_Opened = 2;
		spin_unlock(g_pAF_SpinLock);
	}

	if (g_u4CurrPosition == a_u4Position)
		return 0;

	spin_lock(g_pAF_SpinLock);
	g_u4TargetPosition = a_u4Position;
	spin_unlock(g_pAF_SpinLock);

	/* LOG_INF("move [curr] %d [target] %d\n", g_u4CurrPosition, g_u4TargetPosition); */

	/* s4AF_WriteReg(0x02, 0x00); */

	if (setVCMPos(g_u4TargetPosition) == 0) {
		spin_lock(g_pAF_SpinLock);
		g_u4CurrPosition = (unsigned long)g_u4TargetPosition;
		spin_unlock(g_pAF_SpinLock);
	} else {
		LOG_INF("set I2C failed when moving the motor\n");
	}

	return 0;
}

static inline int setAFInf(unsigned long a_u4Position)
{
	spin_lock(g_pAF_SpinLock);
	g_u4AF_INF = a_u4Position;
	spin_unlock(g_pAF_SpinLock);
	return 0;
}

static inline int setAFMacro(unsigned long a_u4Position)
{
	spin_lock(g_pAF_SpinLock);
	g_u4AF_MACRO = a_u4Position;
	spin_unlock(g_pAF_SpinLock);
	return 0;
}

/*
 * AFIOC_S_SETPARA, sent by libcam.hal3a.v3.so as mcuIOC_T_SETPARA during an
 * active AF scan. Without a case for it the switch below fell through to
 * default and answered -EPERM, which the 3A blob reported as
 * "[setMCUMacroPos] ioctl - mcuIOC_T_SETPARA, error Operation not permitted"
 * and which left AF stuck in ACTIVE_UNFOCUSED, so no capture ever completed.
 * Modelled on BU63165AF.c:187 - accept the command, log what was asked for, and
 * succeed. The only CmdID that driver acts on is 1 (OIS mode); AK7371 has no
 * OIS, so there is nothing to do here beyond reporting it. The log is
 * deliberate: it is the first look we get at the CmdID the blob actually sends.
 */
static inline int setAFPara(__user stAF_MotorCmd * pstMotorCmd)
{
	stAF_MotorCmd stMotorCmd;

	if (copy_from_user(&stMotorCmd, pstMotorCmd, sizeof(stMotorCmd)))
		LOG_INF("copy from user failed when getting motor command\n");

	LOG_INF("Motor CmdID : %x, Param : %x\n", stMotorCmd.u4CmdID, stMotorCmd.u4Param);

	return 0;
}

/*
 * Bring-up instrument, not part of normal operation.
 *
 * The 3A blob computes focus targets every frame but never issues
 * AFIOC_T_MOVETO, so nothing has ever established whether this actuator can
 * move at all. This knob drives moveAF() directly and reports the result, which
 * splits "the blob never asks" from "the motor cannot move":
 *
 *   echo 600 > /sys/module/AK7371AF/parameters/dbg_move
 *   cat      /sys/module/AK7371AF/parameters/dbg_move
 *   dmesg | grep dbg_move
 *
 * It needs the I2C client, which AK7371AF_SetI2Cclient only installs once the
 * camera HAL has opened /dev/MAINAF and selected this motor, so open the camera
 * first; without it the pointers are NULL and this would oops rather than
 * report. Hence the guard.
 */
static int af_dbg_move_set(const char *val, const struct kernel_param *kp)
{
	unsigned long pos;
	int ret;

	if (!g_pstAF_I2Cclient || !g_pAF_SpinLock || !g_pAF_Opened) {
		pr_info(AF_DRVNAME " [dbg_move] not bound yet - start the camera first\n");
		return -ENODEV;
	}

	ret = kstrtoul(val, 0, &pos);
	if (ret)
		return ret;

	pr_info(AF_DRVNAME " [dbg_move] request %lu (curr %lu inf %lu macro %lu opened %d)\n",
		pos, g_u4CurrPosition, g_u4AF_INF, g_u4AF_MACRO, *g_pAF_Opened);

	ret = moveAF(pos);

	pr_info(AF_DRVNAME " [dbg_move] moveAF returned %d, curr now %lu\n",
		ret, g_u4CurrPosition);

	return ret;
}

static int af_dbg_move_get(char *buf, const struct kernel_param *kp)
{
	return scnprintf(buf, PAGE_SIZE,
			 "curr %lu target %lu inf %lu macro %lu opened %d\n",
			 g_u4CurrPosition, g_u4TargetPosition,
			 g_u4AF_INF, g_u4AF_MACRO,
			 g_pAF_Opened ? *g_pAF_Opened : -1);
}

static struct kernel_param_ops af_dbg_move_ops = {
	.set = af_dbg_move_set,
	.get = af_dbg_move_get,
};
module_param_cb(dbg_move, &af_dbg_move_ops, NULL, 0644);

/* ////////////////////////////////////////////////////////////// */
long AK7371AF_Ioctl(struct file *a_pstFile, unsigned int a_u4Command, unsigned long a_u4Param)
{
	long i4RetValue = 0;

	switch (a_u4Command) {
	case AFIOC_G_MOTORINFO:
		i4RetValue = getAFInfo((__user stAF_MotorInfo *) (a_u4Param));
		break;

	case AFIOC_T_MOVETO:
		i4RetValue = moveAF(a_u4Param);
		break;

	case AFIOC_T_SETINFPOS:
		i4RetValue = setAFInf(a_u4Param);
		break;

	case AFIOC_T_SETMACROPOS:
		i4RetValue = setAFMacro(a_u4Param);
		break;

	case AFIOC_S_SETPARA:
		i4RetValue = setAFPara((__user stAF_MotorCmd *) (a_u4Param));
		break;

	default:
		LOG_INF("No CMD\n");
		i4RetValue = -EPERM;
		break;
	}

	return i4RetValue;
}

static int g_AF_Power = 0;

#ifdef MEIZU_M80
/*****Interface for factory test*****/
extern int Camera_AF_PowerOn(bool on);
extern int iReadRegI2C(u8 *a_pSendData , u16 a_sizeSendData, u8 * a_pRecvData, u16 a_sizeRecvData, u16 i2cId);
extern int iWriteRegI2C(u8 *a_pSendData , u16 a_sizeSendData, u16 i2cId);

static u8 read_af_reg(u8 addr)
{
    u8 get_byte=0;

    char pu_send_cmd[1] = {(char)(addr & 0xFF) };
    iReadRegI2C(pu_send_cmd, 1, (u8*)&get_byte, 1,AF_I2C_SLAVE_ADDR );

    return get_byte;
}

static void write_af_reg(u8 addr, u8 para)
{
    char pu_send_cmd[2] = {(char)(addr & 0xFF), (char)(para & 0xFF)};
    iWriteRegI2C(pu_send_cmd, 2, AF_I2C_SLAVE_ADDR);
}

int Factory_Move_AF(unsigned long a_u4Position){

	unsigned short InitPos, InitPosM, InitPosL;
	
	if (g_pAF_Opened == NULL && g_AF_Power == 0) {
		LOG_INF("Power on AF device\n");
		Camera_AF_PowerOn(true);
		msleep(200);
		g_AF_Power = 1;
	}
	else{
		LOG_INF("AF device has been opened,no need to power on again\n");
	}
	
	/* 00:active mode        10:Standby mode    x1:Sleep mode */
	write_af_reg(0x02, 0x00);	/* from Standby mode to Active mode */
	msleep(20);
	
	if(a_u4Position != 0){
		write_af_reg(0x0, (u16)((a_u4Position >> 2) & 0xff));
		write_af_reg(0x1, (u16) ((a_u4Position & 0x3) << 6));
	}
	else
		LOG_INF("Current position\n");
		
	InitPosM = read_af_reg(0x0);
	InitPosL = read_af_reg(0x1);
	InitPos = ((InitPosM & 0xFF) << 2) + ((InitPosL >> 6) & 0x3);
		
	return InitPos; 
}
#endif

/* Main jobs: */
/* 1.Deallocate anything that "open" allocated in private_data. */
/* 2.Shut down the device on last close. */
/* 3.Only called once on last time. */
/* Q1 : Try release multiple times. */
int AK7371AF_Release(struct inode *a_pstInode, struct file *a_pstFile)
{
	LOG_INF("Start\n");

	if (*g_pAF_Opened == 2) {
		LOG_INF("Wait\n");
		s4AF_WriteReg(0x02, 0x20);
		msleep(20);
	}

	if (*g_pAF_Opened) {
		LOG_INF("Free\n");

		spin_lock(g_pAF_SpinLock);
		*g_pAF_Opened = 0;
		spin_unlock(g_pAF_SpinLock);
	}

	LOG_INF("End\n");

	return 0;
}

void AK7371AF_SetI2Cclient(struct i2c_client *pstAF_I2Cclient, spinlock_t *pAF_SpinLock, int *pAF_Opened)
{
	g_pstAF_I2Cclient = pstAF_I2Cclient;
	g_pAF_SpinLock = pAF_SpinLock;
	g_pAF_Opened = pAF_Opened;
}
