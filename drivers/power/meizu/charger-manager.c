/*****************************************************************************
 * Description:
 * ------------
 *   This Module defines functions of mz Battery charging algorithm
 *   and the Anroid Battery service for updating the battery status
 *
 ****************************************************************************/
#include <linux/init.h>		/* For init/exit macros */
#include <linux/module.h>	/* For MODULE_ marcros  */
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/power_supply.h>
#include <linux/of.h>
#include <linux/wakelock.h>
#include <linux/time.h>
#include <linux/alarmtimer.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/scatterlist.h>
#include <linux/suspend.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <mt-plat/mtk_thermal_typedefs.h>
#include <mt-plat/mt_boot_common.h>
#include <mt-plat/charging.h>
#include <mt-plat/battery_common.h>
#include <linux/meizu-sys.h>
#include <mach/mt_pe.h>
#include <linux/power/bq2589x_reg.h>
#include <linux/power/bq27532_battery.h>

PMU_ChargerStruct BMT_status;
CHARGING_CONTROL battery_charging_control;
extern bool upmu_is_chr_det(void);

static kal_bool bat_thread_timeout = KAL_FALSE;
static DEFINE_MUTEX(bat_mutex);
static DEFINE_MUTEX(charger_type_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bat_thread_wq);
static struct alarm battery_kthread_timer;
struct wake_lock chgin_wakelock;

int cmd_discharging = -1;

static bool temperature_debug = KAL_FALSE;
static bool batvol_debug = KAL_FALSE;

static kal_bool g_bat_init_flag = 0;
extern int set_usb_cooling_listener(void (*listener)(int is_hot, int temp));

#define QUICK_CHARGER 1
#define NORMAL_CHARGER 0
/*0:ATLL,1:SDI,2:LG*/
/*
 typedef struct {
	int batt_temperature;
	int batt_temp_stat;
	kal_bool is_increase;
	int target_vol;
	CHR_CURRENT_ENUM charger_current;
	CHR_CURRENT_ENUM input_current;
} BATTERY_TEMP_STRUCT;
 */
static BATTERY_TEMP_STRUCT battery_temp_stat_table[3][8] = 
{
	{
		{0, TEMP_POS_LOW, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT},
		{10, TEMP_POS_T10, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGING_0_3C_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{20, TEMP_POS_T20, QUICK_CHARGER, VOLTAGE_12V_SUPPORT, AC_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{41, TEMP_POS_T41, QUICK_CHARGER, VOLTAGE_12V_SUPPORT, TA_AC_1_5C_CHARGING_CURRENT, TA_AC_12V_INPUT_CURRENT},
		{43, TEMP_POS_T43, QUICK_CHARGER, VOLTAGE_9V_SUPPORT, TA_AC_1C_CHARGING_CURRENT, TA_AC_9V_INPUT_CURRENT},
		{46, TEMP_POS_NORMAL, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, AC_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{61, TEMP_POS_HIGH, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT}
	},
	{
		{0, TEMP_POS_LOW, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT},
		{10, TEMP_POS_T10, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGING_0_3C_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{15, TEMP_POS_T15, QUICK_CHARGER, VOLTAGE_12V_SUPPORT, AC_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{41, TEMP_POS_T41, QUICK_CHARGER, VOLTAGE_12V_SUPPORT, TA_AC_1_5C_CHARGING_CURRENT, TA_AC_12V_INPUT_CURRENT},
		{43, TEMP_POS_T43, QUICK_CHARGER, VOLTAGE_9V_SUPPORT, TA_AC_1C_CHARGING_CURRENT, TA_AC_9V_INPUT_CURRENT},
		{46, TEMP_POS_NORMAL, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, AC_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{61, TEMP_POS_HIGH, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT}
	},
	{
		{0, TEMP_POS_LOW, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT},
		{10, TEMP_POS_T10, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGING_0_3C_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{20, TEMP_POS_T20, QUICK_CHARGER, VOLTAGE_12V_SUPPORT, AC_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{41, TEMP_POS_T41, QUICK_CHARGER, VOLTAGE_12V_SUPPORT, TA_AC_1_5C_CHARGING_CURRENT, TA_AC_12V_INPUT_CURRENT},
		{43, TEMP_POS_T43, QUICK_CHARGER, VOLTAGE_9V_SUPPORT, TA_AC_1C_CHARGING_CURRENT, TA_AC_9V_INPUT_CURRENT},
		{46, TEMP_POS_NORMAL, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, AC_CHARGER_CURRENT, AC_CHARGER_CURRENT},
		{61, TEMP_POS_HIGH, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT}
	}
};

struct ac_data {
	struct power_supply psy;
	int AC_ONLINE;
};

struct usb_data {
	struct power_supply psy;
	int USB_ONLINE;
};

struct battery_data {
	struct power_supply psy;
	int batt_status;
	int batt_health;
	int batt_present;
	int capacity;
	int voltage_now;
	int curr_now;
	int batt_temp;
	int current_now;
	int current_avg;
	int batt_chargervol;
	int adjust_power;
};

static enum power_supply_property ac_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_CURRENT_MAX,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
};

static enum power_supply_property usb_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_CURRENT_MAX,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
};

static enum power_supply_property battery_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_batt_vol,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CHARGE_COUNTER,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_MANUFACTURER,
	POWER_SUPPLY_PROP_adjust_power,
};

static bool usb_unlimited=false;
CHR_CURRENT_ENUM g_temp_input_CC_value = CHARGE_CURRENT_0_00_MA;
CHR_CURRENT_ENUM g_temp_CC_value = CHARGE_CURRENT_0_00_MA;

void wake_up_bat(void)
{
	printk("[BATTERY] wake_up_bat. \r\n");

	bat_thread_timeout = KAL_TRUE;
	wake_up(&bat_thread_wq);
}
EXPORT_SYMBOL(wake_up_bat);

/* Input limit the charging path is currently allowed to draw from VBUS,
 * in uA for the power_supply ABI (healthd "Max charging current").
 * CHR_CURRENT_ENUM encodes current in units of 10 uA. */
static int charger_input_current_max_uA(void)
{
	return (int)g_temp_input_CC_value * 10;
}

/* Live VBUS voltage from the bq2589x ADC in uV (the ADC reports mV).
 * Falls back to the nominal 5 V if the read fails, so healthd never
 * sees a negative errno as a voltage. */
static int charger_voltage_max_uV(void)
{
	int mv = bq2589x_adc_read_charger_volt();

	if (mv <= 0)
		mv = 5000;
	return mv * 1000;
}

static int ac_get_property(struct power_supply *psy,
			   enum power_supply_property psp, union power_supply_propval *val)
{
	int ret = 0;
	struct ac_data *data = container_of(psy, struct ac_data, psy);

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = data->AC_ONLINE;
		break;
	case POWER_SUPPLY_PROP_CURRENT_MAX:
		val->intval = charger_input_current_max_uA();
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		val->intval = charger_voltage_max_uV();
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int usb_get_property(struct power_supply *psy,
			    enum power_supply_property psp, union power_supply_propval *val)
{
	int ret = 0;
	struct usb_data *data = container_of(psy, struct usb_data, psy);

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = data->USB_ONLINE;
		break;
	case POWER_SUPPLY_PROP_CURRENT_MAX:
		val->intval = charger_input_current_max_uA();
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		val->intval = charger_voltage_max_uV();
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int battery_get_property(struct power_supply *psy,
		enum power_supply_property psp,union power_supply_propval *val)
{
	int ret = 0;
	struct battery_data *data = container_of(psy, struct battery_data, psy);

	switch (psp) {
		case POWER_SUPPLY_PROP_STATUS:
			val->intval = data->batt_status;
			break;
		case POWER_SUPPLY_PROP_HEALTH:
			val->intval = data->batt_health;
			break;
		case POWER_SUPPLY_PROP_PRESENT:
			val->intval = data->batt_present;
			break;
		case POWER_SUPPLY_PROP_MANUFACTURER:
			val->strval = BMT_status.manufacturer_name;
			break;
		case POWER_SUPPLY_PROP_CAPACITY:
			if (BMT_status.g_platform_boot_mode == RECOVERY_BOOT) {
				battery_charging_control(CHARGING_CMD_GET_BATTERYSOC, &BMT_status.SOC);
				val->intval = BMT_status.SOC;
			} else 
				val->intval = data->capacity;
			break;
		case POWER_SUPPLY_PROP_VOLTAGE_NOW:
			/* power_supply ABI is uV; BMT_status.bat_vol is mV.
			 * batt_vol below stays in mV: the camera 3A HAL
			 * (libcam.hal3a.v3.so) reads it as mV. */
			val->intval = data->voltage_now * 1000;
			break;
		case POWER_SUPPLY_PROP_batt_vol:
			val->intval = data->voltage_now;
			break;
		case POWER_SUPPLY_PROP_CURRENT_NOW:
			battery_charging_control(CHARGING_CMD_GET_BATTERYCURR_NOW, &data->curr_now);
			/* bq27532 NOW_CURR is a signed 16-bit value in mA
			 * (negative = discharging); the ABI wants uA. */
			val->intval = (int)(s16)(data->curr_now & 0xffff) * 1000;
			break;
		case POWER_SUPPLY_PROP_CHARGE_COUNTER:
			/* uAh remaining capacity from the bq27532 gauge */
			val->intval = bq27532_battery_read_remaining_capacity();
			break;
		case POWER_SUPPLY_PROP_TEMP:
			val->intval = data->batt_temp;
			break;
		case POWER_SUPPLY_PROP_TECHNOLOGY:
			val->intval = POWER_SUPPLY_TECHNOLOGY_LION;
			break;
		case POWER_SUPPLY_PROP_adjust_power:
			val->intval = data->adjust_power;
			break;
		default:
			return -EINVAL;
	}
	return ret;
}

static int battery_set_property(struct power_supply *psy,
		enum power_supply_property psp,
		const union power_supply_propval *val)
{
	switch (psp) {
	case POWER_SUPPLY_PROP_TEMP:
	    BMT_status.temperature= val->intval;
	    temperature_debug = true;
	    wake_up_bat();
	    break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
	    BMT_status.bat_vol = val->intval;
	    batvol_debug = true;
	    break;
	default:
	    break;
	}
	return 0;
}

/* ac_data initialization */
static struct ac_data ac_main = {
	.psy = {
		.name = "ac",
		.type = POWER_SUPPLY_TYPE_MAINS,
		.properties = ac_props,
		.num_properties = ARRAY_SIZE(ac_props),
		.get_property = ac_get_property,
		},
	.AC_ONLINE = 0,
};

/* usb_data initialization */
static struct usb_data usb_main = {
	.psy = {
		.name = "usb",
		.type = POWER_SUPPLY_TYPE_USB,
		.properties = usb_props,
		.num_properties = ARRAY_SIZE(usb_props),
		.get_property = usb_get_property,
		},
	.USB_ONLINE = 0,
};

/* battery_data initialization */
static struct battery_data battery_main = {
	.psy = {
		.name = "battery",
		.type = POWER_SUPPLY_TYPE_BATTERY,
		.properties = battery_props,
		.num_properties = ARRAY_SIZE(battery_props),
		.get_property = battery_get_property,
		.set_property = battery_set_property,	
		},
	.batt_present = 1, 
	.capacity = 50,
	.voltage_now = 3800,
	.batt_temp = 25,
};

static void ac_update(struct ac_data *ac_data)
{
	struct power_supply *ac_psy = &ac_data->psy;

	if (BMT_status.charger_exist == KAL_TRUE) {
		if ((BMT_status.charger_type != STANDARD_HOST) &&
				(BMT_status.charger_type != CHARGING_HOST)) {
			ac_data->AC_ONLINE = 1;
			ac_psy->type = POWER_SUPPLY_TYPE_MAINS;
		} else {
			ac_data->AC_ONLINE = 0;
		}
	} else {
		ac_data->AC_ONLINE = 0;
	}

	power_supply_changed(ac_psy);
}

static void usb_update(struct usb_data *usb_data)
{
	struct power_supply *usb_psy = &usb_data->psy;

	if (BMT_status.charger_exist == KAL_TRUE) {
		if ((BMT_status.charger_type == STANDARD_HOST) ||
		    (BMT_status.charger_type == CHARGING_HOST)) {
			usb_data->USB_ONLINE = 1;
			usb_psy->type = POWER_SUPPLY_TYPE_USB;
		} else {
			usb_data->USB_ONLINE = 0;
		}
	} else {
		usb_data->USB_ONLINE = 0;
	}

	power_supply_changed(usb_psy);
}

/*
 * 1 (default): report FULL on the cable once the gauge SOC is 100 and
 * DISCHARGING without a charger. 0: the vendor CHARGING/NOT_CHARGING, which
 * Android shows as never "Charged" and "Not charging" on battery.
 */
static int forge_status_full = 1;
module_param(forge_status_full, int, 0644);
MODULE_PARM_DESC(forge_status_full,
	"1 = FULL at SOC 100 on the cable and DISCHARGING on battery (default), 0 = stock CHARGING/NOT_CHARGING");

static void battery_update(struct battery_data *bat_data)
{
	struct power_supply *bat_psy = &bat_data->psy;

	bat_data->voltage_now = BMT_status.bat_vol;
	bat_data->batt_temp = BMT_status.temperature * 10;
	bat_data->batt_present = BMT_status.bat_exist;
	bat_data->capacity = BMT_status.SOC;
	bat_data->adjust_power = -1;

	if (BMT_status.batt_status == TEMP_POS_LOW) {
		bat_data->batt_health = POWER_SUPPLY_HEALTH_COLD;
	} else if (BMT_status.batt_status == TEMP_POS_HIGH) {
		bat_data->batt_health = POWER_SUPPLY_HEALTH_OVERHEAT;
	} else {
		bat_data->batt_health = POWER_SUPPLY_HEALTH_GOOD;
	}

	if (BMT_status.charger_exist == KAL_TRUE) {     
		bat_data->batt_status = POWER_SUPPLY_STATUS_CHARGING;  
		/* see forge_status_full: the gauge at 100 % on the cable */
		if (forge_status_full && BMT_status.SOC >= 100)
			bat_data->batt_status = POWER_SUPPLY_STATUS_FULL;
	} else {	/* Only Battery */
		bat_data->batt_status = forge_status_full ?
			POWER_SUPPLY_STATUS_DISCHARGING :
			POWER_SUPPLY_STATUS_NOT_CHARGING;
	} 

	if (cmd_discharging == 1 || BMT_status.batt_status == TEMP_POS_LOW ||
			BMT_status.batt_status == TEMP_POS_HIGH ||
			BMT_status.usb_thermal == true) {
		bat_data->batt_status = POWER_SUPPLY_STATUS_DISCHARGING;
	}

	power_supply_changed(bat_psy);
}

kal_bool bat_is_charging_full(void)
{
	if ((BMT_status.bat_full == KAL_TRUE) && (BMT_status.bat_in_recharging_state == KAL_FALSE))
		return KAL_TRUE;
	else
		return KAL_FALSE;
}

bool get_usb_current_unlimited(void)
{
	if ((BMT_status.charger_type == STANDARD_HOST)
			|| (BMT_status.charger_type == CHARGING_HOST))
		return usb_unlimited;
	else
		return false;
}

void set_usb_current_unlimited(bool enable)
{
	if ((BMT_status.g_platform_boot_mode == LOW_POWER_OFF_CHARGING_BOOT)
			|| (BMT_status.g_platform_boot_mode == KERNEL_POWER_OFF_CHARGING_BOOT)) {
		usb_unlimited = false;
	} else {
		usb_unlimited = enable;
	}
}

static void bq2589x_battery_GetBatteryData(void)
{
	if (temperature_debug == KAL_FALSE)
		battery_charging_control(CHARGING_CMD_GET_BATTERYTEMP, &BMT_status.temperature);
	if (batvol_debug == KAL_FALSE)
		battery_charging_control(CHARGING_CMD_GET_BATTERYVOL, &BMT_status.bat_vol);
	battery_charging_control(CHARGING_CMD_GET_BATTERYCURR, &BMT_status.ICharging);
	battery_charging_control(CHARGING_CMD_GET_BATTERYSOC, &BMT_status.SOC);
	printk("%s: voltage %d, temperature %d, current %d, soc %d, charger type %d\n", __func__,
			BMT_status.bat_vol, BMT_status.temperature, BMT_status.ICharging, 
			BMT_status.SOC, BMT_status.charger_type);
}

/*
 * The stock Flyme 8 kernel charges at 2050 mA (AC_CHARGER_CURRENT) where
 * this BSP uses 1500 mA. 1 (default): 2050 mA in the T20/T15 row (10-20 C,
 * SDI 10-15 C) only; all other rows and input limits are unchanged.
 * 0: 1500 mA.
 */
static int forge_flyme8_ac = 1;
module_param(forge_flyme8_ac, int, 0644);
MODULE_PARM_DESC(forge_flyme8_ac, "MX6: 2050 mA (Flyme 8) instead of 1500 at 10-20 C (SDI 10-15) on a 5 V charger (1, default)");

/*
 * PE+ table set B, used by the stock kernel on board revision 1 (low nibble
 * of the u32 at +4 of the LK "atag,lk_info" property in /chosen). In the
 * PE+ branch each row's own current and input are used instead of the fixed
 * 9/12 V ones:
 *   <0 stop; 0-10 C 5 V 900 mA; 10-38 C 9 V 3000 mA, input 2000 mA;
 *   38-41 C 9 V 2250 / 1500 mA; 41-46 C 5 V AC_CHARGER_CURRENT; 46-61 C stop.
 * 1 (default): set B on a revision 1 board, set A otherwise. 0: always set A.
 */
static int forge_pe_set_b = 1;
module_param(forge_pe_set_b, int, 0644);
MODULE_PARM_DESC(forge_pe_set_b, "MX6: Flyme 8 PE+ table set B (9 V 3 A at 10-38 C) on board revision 1 (1, default), or set A always (0)");

#define FORGE_TEMP_POS_T38	38

static BATTERY_TEMP_STRUCT forge_pe_set_b_table[8] = {
	{0, TEMP_POS_LOW, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT},
	{10, TEMP_POS_T10, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGING_0_3C_CHARGER_CURRENT, AC_CHARGER_CURRENT},
	{38, FORGE_TEMP_POS_T38, QUICK_CHARGER, VOLTAGE_9V_SUPPORT, CHARGE_CURRENT_3000_00_MA, CHARGE_CURRENT_2000_00_MA},
	{41, TEMP_POS_T41, QUICK_CHARGER, VOLTAGE_9V_SUPPORT, TA_AC_1_5C_CHARGING_CURRENT, TA_AC_9V_INPUT_CURRENT},
	{46, TEMP_POS_NORMAL, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, AC_CHARGER_CURRENT, AC_CHARGER_CURRENT},
	{61, TEMP_POS_HIGH, NORMAL_CHARGER, VOLTAGE_5V_SUPPORT, CHARGE_CURRENT_0_00_MA, AC_CHARGER_CURRENT}
};

/* LK board revision; -1 = unknown */
static int forge_board_rev(void)
{
	static int rev = -2;
	struct device_node *np;
	const __be32 *p;
	int len = 0;

	if (rev != -2)
		return rev;
	rev = -1;
	np = of_find_node_by_path("/chosen");
	if (!np)
		np = of_find_node_by_path("/chosen@0");
	if (np) {
		p = of_get_property(np, "atag,lk_info", &len);
		if (p && len >= 8)
			rev = le32_to_cpup((const __le32 *)((const u8 *)p + 4)) & 0xF;
		of_node_put(np);
	}
	pr_info("[BATTERY] board revision %d (atag,lk_info %d bytes): PE+ table set %s\n",
		rev, len, rev == 1 && forge_pe_set_b ? "B" : "A");
	return rev;
}

static bool forge_set_b(void)
{
	return forge_pe_set_b && forge_board_rev() == 1;
}

static void battery_get_temp_stat(signed int temperature, int battery_id)
{
	BATTERY_TEMP_STRUCT *batt_temp_stat_table = forge_set_b() ?
		forge_pe_set_b_table : battery_temp_stat_table[battery_id];
	int i = 0, last = 0;

	/*
	 * Stop at the table end or the zero terminator row; with no match
	 * use the last row (TEMP_POS_HIGH, 0 mA), so charging stops.
	 */
	for (i = 0; i < ARRAY_SIZE(battery_temp_stat_table[0]); i++) {
		if (i && !batt_temp_stat_table[i].batt_temperature)
			break;
		last = i;
		if (temperature < batt_temp_stat_table[i].batt_temperature)
			break;
	}
	i = last;
	if (temperature >= batt_temp_stat_table[i].batt_temperature)
		BMT_status.batt_status = TEMP_POS_HIGH;
	else
		BMT_status.batt_status = batt_temp_stat_table[i].batt_temp_stat;

	g_temp_CC_value = batt_temp_stat_table[i].charger_current;
	g_temp_input_CC_value = batt_temp_stat_table[i].input_current;
	if (forge_flyme8_ac && g_temp_CC_value == AC_CHARGER_CURRENT &&
	    (BMT_status.batt_status == TEMP_POS_T20 ||
	     BMT_status.batt_status == TEMP_POS_T15))
		g_temp_CC_value = CHARGE_CURRENT_2050_00_MA;
	BMT_status.g_qcct_flag = batt_temp_stat_table[i].is_increase;
	BMT_status.target_voltage = batt_temp_stat_table[i].target_vol;

	if (BMT_status.pre_batt_status != BMT_status.batt_status)
		BMT_status.qc_check_flag = KAL_FALSE;

	BMT_status.pre_batt_status = BMT_status.batt_status;
}

static PMU_STATUS bq2589x_battery_CheckBatteryTemp(void)
{
	int board_temp = 0;

	if (BMT_status.temperature == ERR_CHARGE_TEMPERATURE) {
		return PMU_STATUS_FAIL;
	}
	if (BMT_status.boardtemp_debug == -1)
		board_temp = get_mtk_bts_temp() / 1000;
	else
		board_temp = BMT_status.boardtemp_debug;
	printk("%s:board_temp %d, BMT_status.temperature %d\n",
			__func__, board_temp, BMT_status.temperature);
	
	if (board_temp >= TEMP_POS_T41 && board_temp <= TEMP_POS_T45)
		BMT_status.temperature = max(board_temp, BMT_status.temperature);
	else if (board_temp > TEMP_POS_T45 && (BMT_status.temperature <= TEMP_POS_T45
				&& BMT_status.temperature >= TEMP_POS_LOW))
		BMT_status.temperature = TEMP_POS_T45;
	battery_get_temp_stat(BMT_status.temperature, BMT_status.battery_id);

	if (BMT_status.batt_status == TEMP_POS_LOW || BMT_status.batt_status == TEMP_POS_HIGH) {
		return PMU_STATUS_FAIL;
	} else {
		return PMU_STATUS_OK;
	}
}

static void bq2589x_battery_check_batterycv(void)
{
	kal_bool cv_change = 0;

	battery_charging_control(CHARGING_CMD_CHECK_BATTERYCV, &cv_change);
	if (cv_change == KAL_TRUE) {
		BMT_status.g_qcct_flag = NORMAL_CHARGER;
	} else {
		BMT_status.g_qcct_flag = QUICK_CHARGER;
	}
}

static void bq2589x_battery_CheckBatteryStatus(void)
{
	if (cmd_discharging == 1) { //产线测试接口
		BMT_status.bat_charging_state = CHR_ERROR;
		return;
	} else if (cmd_discharging == 0) {
		BMT_status.bat_charging_state = CHR_CC;
		cmd_discharging = -1;
	}
	if (bq2589x_battery_CheckBatteryTemp() != PMU_STATUS_OK) {
		BMT_status.bat_charging_state = CHR_ERROR;
	} else {
		BMT_status.bat_charging_state = CHR_CC;
	}

	if (BMT_status.g_qcct_flag == QUICK_CHARGER)
		bq2589x_battery_check_batterycv();

	if (BMT_status.SOC > TA_STOP_BATTERY_SOC)
		BMT_status.g_qcct_flag = NORMAL_CHARGER;
}

void bq2589x_charge_update_status(void)
{
	ac_update(&ac_main);
	usb_update(&usb_main);
	battery_update(&battery_main);
}

static void charger_termination_done_check(void)
{
	kal_uint32 charging_enable = KAL_FALSE;
	int charging_stat = 0;

	battery_charging_control(CHARGING_CMD_GET_CHARGING_STATUS, &charging_stat);
	if (charging_stat == CHARGE_TERMINATION_DONE && BMT_status.SOC != 100) {
		printk("%s:Charge Termination Done\n", __func__);
		charging_enable = KAL_FALSE;
		battery_charging_control(CHARGING_CMD_ENABLE, &charging_enable);
		msleep(250);
		charging_enable = KAL_TRUE;
		battery_charging_control(CHARGING_CMD_ENABLE, &charging_enable);
		BMT_status.qc_check_flag = KAL_FALSE;
	}
}

#define CHARGER_TYPE_DET_COUNTER	5
static void bq2589x_battery_charger_detect_check(void)
{
	int chr_det, usb_status;
	CHARGER_TYPE CHR_Type_num = CHARGER_UNKNOWN;
	static int det_count = 0;

	battery_charging_control(CHARGING_CMD_GET_CHARGER_DET_STATUS, &chr_det);
	if (chr_det == KAL_TRUE) {
		BMT_status.charger_exist = KAL_TRUE;
		mutex_lock(&charger_type_mutex);
		if ((BMT_status.charger_type == CHARGER_UNKNOWN || BMT_status.charger_type == NONSTANDARD_CHARGER) &&
				(det_count <= CHARGER_TYPE_DET_COUNTER)) {
			det_count++;
			battery_charging_control(CHARGING_CMD_GET_CHARGER_TYPE, &CHR_Type_num);
			BMT_status.charger_type = CHR_Type_num;
			/* start for charger type detect error*/
			if (BMT_status.charger_type == NONSTANDARD_CHARGER &&
					BMT_status.bat_task_timer != BAT_TASK_CHECKTYPE_PERIOD) {
				BMT_status.bat_task_timer = BAT_TASK_CHECKTYPE_PERIOD;
				wake_up_bat();
			}
			if ((det_count >= CHARGER_TYPE_DET_COUNTER || BMT_status.charger_type != NONSTANDARD_CHARGER) &&
					(BMT_status.bat_task_timer != BAT_TASK_DEFAULT_PERIOD)) {
				BMT_status.bat_task_timer = BAT_TASK_DEFAULT_PERIOD;
				wake_up_bat();
			}
			/* end */
			if ((BMT_status.charger_type == STANDARD_HOST)
			    || (BMT_status.charger_type == CHARGING_HOST)) {
				usb_status = KAL_TRUE;
				battery_charging_control(CHARGING_CMD_MT_USB_CONNECT, &usb_status);
			}
		}
		mutex_unlock(&charger_type_mutex);
		printk("Cable in, CHR_Type_num=%d\r\n", BMT_status.charger_type);
	} else {
		printk("Cable out \r\n");
		BMT_status.charger_exist = KAL_FALSE;
		BMT_status.charger_type = CHARGER_UNKNOWN;
		det_count = 0; 
		usb_status = KAL_FALSE;
		battery_charging_control(CHARGING_CMD_MT_USB_CONNECT, &usb_status);
		#if !defined(MEIZU_FACTORY_BUILD)
		if (chgin_wakelock.ws.active)
			wake_unlock(&chgin_wakelock);
		#endif
	}
	bq2589x_charge_update_status();
}

void do_chrdet_int_task(void)
{
	kal_bool det_stat = KAL_FALSE;
	kal_uint32 charging_enable = KAL_FALSE;

	if (g_bat_init_flag == KAL_TRUE) {
		battery_charging_control(CHARGING_CMD_GET_CHARGER_DET_STATUS, &det_stat);
		if (det_stat == KAL_TRUE) {
		#if !defined(MEIZU_FACTORY_BUILD)
			wake_lock(&chgin_wakelock);
		#else
			wake_lock_timeout(&chgin_wakelock, 3*HZ);
		#endif
			printk("[do_chrdet_int_task] charger exist!\n");
			BMT_status.charger_exist = KAL_TRUE;
			BMT_status.qc_connect = KAL_FALSE;
			BMT_status.qc_check_flag = KAL_FALSE;
			vbus_change_event = KAL_FALSE;
			BMT_status.adapter_num = ADAPTER_OUTPUT_0A;
			battery_charging_control(CHARGING_CMD_INIT, NULL);
			bq2589x_battery_charger_detect_check();
		} else {
			printk("[do_chrdet_int_task] charger NOT exist!\n");
			BMT_status.charger_exist = KAL_FALSE;
			battery_charging_control(CHARGING_CMD_SET_ADC_STOP, NULL);
			battery_charging_control(CHARGING_CMD_ENABLE, &charging_enable);
			BMT_status.qc_connect = KAL_FALSE;
			BMT_status.qc_check_flag = KAL_FALSE;
			vbus_change_event = KAL_FALSE;
			BMT_status.adapter_num = ADAPTER_OUTPUT_0A;
		#if !defined(MEIZU_FACTORY_BUILD)
			wake_unlock(&chgin_wakelock);
		#endif
		}
		bq2589x_charge_update_status();
		wake_up_bat();
	}
}

static void select_charging_current_usb(void)
{
	if (BMT_status.charger_type == CHARGING_HOST) {
		g_temp_input_CC_value = CHARGE_CURRENT_1000_00_MA;
		g_temp_CC_value = CHARGE_CURRENT_1000_00_MA;
		return;
	}
	/* Set USB FAST Charging Current */
	if (get_usb_current_unlimited()) {
		g_temp_input_CC_value = USB_CHARGER_INPUT_CURRENT;
		g_temp_CC_value = USB_CHARGER_ONLY_CURRENT;
		if (BMT_status.batt_status == TEMP_POS_T10) {
			g_temp_input_CC_value = CHARGING_0_3C_CHARGER_CURRENT;
			g_temp_CC_value = CHARGING_0_3C_CHARGER_CURRENT;
		}
	} else {
		g_temp_input_CC_value = USB_CHARGER_CURRENT;
		g_temp_CC_value = USB_CHARGER_CURRENT;
	}
}

static void select_charging_curret_bcct(void)
{
	BATTERY_VOLTAGE_ENUM cv_voltage = BATTERY_VOLT_04_350000_V;

	switch (BMT_status.batt_status) {
		case TEMP_POS_T15:
			cv_voltage = BATTERY_VOLT_04_100000_V;
			break;
		case TEMP_POS_T20:
			cv_voltage = BATTERY_VOLT_04_200000_V;
			break;
		default:
			break;
	}
	battery_charging_control(CHARGING_CMD_SET_CV_VOLTAGE, &cv_voltage);
}

extern unsigned int set_chr_input_current_limit(int current_limit)
{
	if (current_limit != -1) {
		BMT_status.g_bcct_input_flag = 1;

		if ((BMT_status.charger_type == STANDARD_HOST) ||
				(BMT_status.charger_type == CHARGING_HOST)) {
			g_temp_input_CC_value = CHARGE_CURRENT_500_00_MA;
			g_temp_CC_value = CHARGE_CURRENT_500_00_MA;
		} else {
			if (current_limit < 650) {
				g_temp_input_CC_value = CHARGE_CURRENT_650_00_MA;
				g_temp_CC_value = CHARGE_CURRENT_650_00_MA;
			} else {
				g_temp_input_CC_value = current_limit * 100;
				g_temp_CC_value = current_limit * 100;
			}
		}
		printk("[BATTERY] %s:(%d)\n", __func__, current_limit);
	} else {
		/* change to default current setting */
		BMT_status.g_bcct_input_flag = 0;
	}
	return BMT_status.g_bcct_input_flag;
}

static void select_charging_curret(void)
{
	CHR_CURRENT_ENUM input_limit = CHARGE_CURRENT_0_00_MA;

	if (BMT_status.batt_status == TEMP_POS_T10)
		return;

	if (BMT_status.adapter_num == ADAPTER_OUTPUT_0A) {
		battery_charging_control(CHARGING_CMD_INPUT_CURRENT_OPTIMITER, &input_limit);
		BMT_status.adapter_num = input_limit;
	}

	if (BMT_status.adapter_num == ADAPTER_OUTPUT_2_0A) {
		g_temp_input_CC_value = CHARGE_CURRENT_1800_00_MA;
	} else if (BMT_status.adapter_num == ADAPTER_OUTPUT_0A) {
		//ICO failed, so set the default charging current
		g_temp_input_CC_value = CHARGE_CURRENT_1100_00_MA;
	} else {
		g_temp_input_CC_value = BMT_status.adapter_num;
	}
}

static void select_qc_charging_curret(void)
{
	/* set B: the row's own current and input */
	if (forge_set_b()) {
		select_charging_curret_bcct();
		return;
	}
	if (BMT_status.target_voltage == VOLTAGE_12V_SUPPORT) {
		g_temp_input_CC_value = TA_AC_12V_INPUT_CURRENT;  //TA = 12V		
		g_temp_CC_value = TA_AC_1_5C_CHARGING_CURRENT;
	} else {
		g_temp_input_CC_value = TA_AC_9V_INPUT_CURRENT;  //TA = 9V		
		g_temp_CC_value = TA_AC_1C_CHARGING_CURRENT;
	}
	select_charging_curret_bcct();
}

static void pchr_turn_on_charging(void)
{
	kal_uint32 charging_enable = KAL_TRUE;
	BATTERY_VOLTAGE_ENUM cv_voltage = BATTERY_VOLT_04_350000_V;

	battery_charging_control(CHARGING_CMD_SET_CV_VOLTAGE, &cv_voltage);

	/*NO1. Set USB Charging Current */
#if defined(MEIZU_FACTORY_BUILD)
	if (BMT_status.charger_type == STANDARD_HOST) {
#else
	if (BMT_status.charger_type == STANDARD_HOST || BMT_status.charger_type == CHARGING_HOST) {
#endif
		select_charging_current_usb();
	} else if (BMT_status.qc_connect == KAL_TRUE) {
		select_qc_charging_curret(); //NO3.快充	
	} else if (BMT_status.g_bcct_input_flag == 0) {
		select_charging_curret();//NO4.常温标准充电
	}
	printk("[BATTERY]CC charging : %d, input current = %d, QC %d, input flag %d\r\n",
			g_temp_CC_value, g_temp_input_CC_value, BMT_status.qc_connect,
			BMT_status.g_bcct_input_flag);

	if (BMT_status.qc_connect == KAL_TRUE) {
		/*set the input current and fast charger current */
		battery_charging_control(CHARGING_CMD_SET_INPUT_CURRENT, &g_temp_input_CC_value);
		battery_charging_control(CHARGING_CMD_SET_CHARGER_CURRENT, &g_temp_CC_value);
		//charging enable
		battery_charging_control(CHARGING_CMD_ENABLE, &charging_enable);
	} else {
		/*set the input current and fast charger current */
		battery_charging_control(CHARGING_CMD_SET_MAIN_INPUT_CURRENT, &g_temp_input_CC_value);
		battery_charging_control(CHARGING_CMD_SET_MAIN_CHARGER_CURRENT, &g_temp_CC_value);
		//charging enable
		battery_charging_control(CHARGING_CMD_ENABLE_MIAN, &charging_enable);
	}
}

/*
 * The vendor code raises VBUS to 9/12 V (PE+) only with the screen off.
 * 0 (default): ignore the screen state; temperature zones,
 * TA_STOP_BATTERY_SOC and mcharger_disable still apply. 1: vendor behaviour.
 */
static int forge_qc_screen_cut;
module_param(forge_qc_screen_cut, int, 0644);
MODULE_PARM_DESC(forge_qc_screen_cut, "MX6: PE+ only with the screen off, as stock (1), or regardless of the screen (0, default)");

static void battery_charger_voltage_increase(void)
{
	int hw_ovp_en = 0; 
	kal_bool screen_on __maybe_unused =
		forge_qc_screen_cut && BMT_status.is_screen_on;
#if defined(MEIZU_FACTORY_BUILD)
	if ((BMT_status.charger_type == STANDARD_CHARGER || BMT_status.charger_type == NONSTANDARD_CHARGER ||
				BMT_status.charger_type == CHARGING_HOST) &&
			(BMT_status.g_qcct_flag == QUICK_CHARGER) && (BMT_status.qc_check_flag == KAL_FALSE)) {
#else
	if ((BMT_status.charger_type == STANDARD_CHARGER || BMT_status.charger_type == NONSTANDARD_CHARGER) &&
			(BMT_status.g_qcct_flag == QUICK_CHARGER) && !screen_on &&
			(BMT_status.qc_check_flag == KAL_FALSE) && (BMT_status.SOC <= TA_STOP_BATTERY_SOC) &&
			(BMT_status.mcharger_disable == 0)) {
#endif
		hw_ovp_en = 0;
		battery_charging_control(CHARGING_CMD_SET_VBUS_OVP_EN, &hw_ovp_en);
		battery_charging_control(CHARGING_CMD_PUMPX_UP, NULL);
#if defined(MEIZU_FACTORY_BUILD)
	} else if (BMT_status.qc_connect == KAL_TRUE && (BMT_status.g_qcct_flag == NORMAL_CHARGER)) {
#else
	} else if (BMT_status.qc_connect == KAL_TRUE && (BMT_status.g_qcct_flag == NORMAL_CHARGER ||
				screen_on || BMT_status.mcharger_disable == 1)) {
#endif
		/* reset the charger voltage*/
		battery_charging_control(CHARGING_CMD_RESET_VCHR, NULL);
		/* default*/
		BMT_status.qc_connect = KAL_FALSE;
		BMT_status.qc_check_flag = KAL_FALSE;
		hw_ovp_en = 1;
		battery_charging_control(CHARGING_CMD_SET_VBUS_OVP_EN, &hw_ovp_en);
	}
}

static void battery_status_fail_action(void)
{
	kal_uint32 charging_enable;

	/*  Disable charger */
	charging_enable = KAL_FALSE;
	
	battery_charging_control(CHARGING_CMD_ENABLE, &charging_enable);
}

static void bq2589x_battery_charging_algorithm(void)
{
	if ((BMT_status.bat_charging_state == CHR_ERROR) || (BMT_status.g_platform_boot_mode == META_BOOT)
			|| (BMT_status.g_platform_boot_mode == ADVMETA_BOOT) ||
			(BMT_status.usb_thermal == true)) {
		battery_status_fail_action();
		BMT_status.qc_connect = KAL_FALSE;
		BMT_status.qc_check_flag = KAL_FALSE;
		return;
	}
	//if charger termination done,but the SOC is not 100% do that.
	charger_termination_done_check();
	battery_charger_voltage_increase();
	/* when in high capacity, change the VINDPM. VBUS less than BAT+VSLEEP (in sleep mode))*/
	battery_charging_control(CHARGING_CMD_SET_VINDPM, NULL);
	/*  Enable charger */
	pchr_turn_on_charging();
	bq2589x_charge_dump_register();
}

void BAT_thread(void)
{
	kal_bool rst_enable = KAL_TRUE;
    kal_uint32 otg_mode = 0 ;/*device mode */
	int hv_voltage = V_CHARGER_MAX * 1000;

	bq2589x_battery_charger_detect_check();
	bq2589x_battery_GetBatteryData();

	bq2589x_charge_update_status();
	/* set the VCDT CHGIN DETECTION THRESHOLD*/
	if (chg_hw_init_done) {
		battery_charging_control(CHARGING_CMD_SET_HV_THRESHOLD, &hv_voltage);
	}

	/*Get usb mode */
    battery_charging_control(CHARGING_CMD_GET_USB_MODE,&otg_mode);
	
	if (BMT_status.charger_exist == KAL_TRUE ||otg_mode) {	
		battery_charging_control(CHARGING_CMD_RESET_WATCH_DOG_TIMER, &rst_enable);
	}
	if (BMT_status.charger_exist == KAL_TRUE && !otg_mode) {	
		bq2589x_battery_CheckBatteryStatus();
		bq2589x_battery_charging_algorithm();
	}
}

int bat_thread_kthread(void *x)
{
	ktime_t ktime = ktime_set(1, 0);

	if (get_boot_mode()== KERNEL_POWER_OFF_CHARGING_BOOT ||
	  	get_boot_mode() ==  LOW_POWER_OFF_CHARGING_BOOT)
		bat_thread_timeout = KAL_TRUE;

	/* Run on a process content */
	while (1) {
		mutex_lock(&bat_mutex);
		BAT_thread();
		mutex_unlock(&bat_mutex);
		wait_event_interruptible(bat_thread_wq, (bat_thread_timeout == KAL_TRUE));

		bat_thread_timeout = KAL_FALSE;
		alarm_start_relative(&battery_kthread_timer, ktime);
		ktime = ktime_set(BMT_status.bat_task_timer, 0);	/* 30s, 10* 1000 ms */
	}
	return 0;
}

void bat_thread_wakeup(void)
{
	bat_thread_timeout = KAL_TRUE;
	wake_up(&bat_thread_wq);
}

static enum alarmtimer_restart battery_kthread_hrtimer_func(struct alarm *alarm, ktime_t time)
{
	bat_thread_wakeup();

	return ALARMTIMER_NORESTART;
}

static void get_charging_control(void)
{
	battery_charging_control = chr_control_interface;
}

static ssize_t show_ADC_Charger_Voltage(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	unsigned int charger_vol;
	int vbus_stat = 0;
	
	charger_vol = bq2589x_adc_read_charger_volt();
	vbus_stat = upmu_is_chr_det(); 
	if (vbus_stat == 0) {
		charger_vol = 0;
	}
	return sprintf(buf, "%d\n",charger_vol);
}
static DEVICE_ATTR(ADC_Charger_Voltage, 0644, show_ADC_Charger_Voltage, NULL);

static ssize_t charger_show_board_temp(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	int board_temp = 0;

	if (BMT_status.boardtemp_debug == -1)
		board_temp = get_mtk_bts_temp() / 1000;
	else
		board_temp = BMT_status.boardtemp_debug;
	return sprintf(buf, "%d\n", board_temp);
}

static ssize_t charger_store_board_temp(struct device *dev,
				struct device_attribute *attr, const char *buf, size_t count)
{
	int val = 0, ret = 0;

	ret = kstrtoint(buf, 10, &val);
	if (ret == -ERANGE || ret == -EINVAL)
		return ret;
	BMT_status.boardtemp_debug = val;
	return count;
}
static DEVICE_ATTR(board_temp, 0644, charger_show_board_temp, charger_store_board_temp);

/* mcharger_disable's function is enable or disable fast charger
	1:disable fast charging
	0:enable fast charging
	defalut:0
 */
static ssize_t charger_show_limit_fastcharging(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", BMT_status.mcharger_disable);
}

static ssize_t charger_store_limit_fastcharging(struct device *dev,
				struct device_attribute *attr, const char *buf, size_t count)
{
	int val = 0, ret = 0;

	ret = kstrtoint(buf, 10, &val);
	if (ret == -ERANGE || ret == -EINVAL)
		return ret;
	BMT_status.mcharger_disable = val;
	wake_up_bat();

	return count;
}
static DEVICE_ATTR(limit_fastcharging, 0644, charger_show_limit_fastcharging,
		charger_store_limit_fastcharging);

static void usb_temp_listener(int is_hot, int temp)
{
	if (is_hot == 1)
		BMT_status.usb_thermal = true;
	else
		BMT_status.usb_thermal = false;

	wake_up_bat();
}

static int battery_probe(struct platform_device *dev)
{
	int ret = 0;
	int chr_det = 0;

	get_charging_control();
	//获取g_platform_boot_mode
	battery_charging_control(CHARGING_CMD_GET_PLATFORM_BOOT_MODE, &BMT_status.g_platform_boot_mode);
	//get the vbus status
	battery_charging_control(CHARGING_CMD_GET_CHARGER_DET_STATUS, &chr_det);
	//init charger hw
	battery_charging_control(CHARGING_CMD_INIT, NULL);
	BMT_status.adapter_num = ADAPTER_OUTPUT_0A;
	BMT_status.target_voltage = VOLTAGE_12V_SUPPORT;
	BMT_status.is_screen_on = KAL_TRUE;
	BMT_status.batt_status = TEMP_POS_NORMAL;
	BMT_status.pre_batt_status = TEMP_POS_NORMAL;
	BMT_status.g_bcct_input_flag = 0;
	BMT_status.qc_check_flag = KAL_FALSE;
	BMT_status.usb_thermal = false;
	BMT_status.mcharger_disable = 0;/*default fast charging*/
	BMT_status.boardtemp_debug = -1;

	if ((BMT_status.g_platform_boot_mode == LOW_POWER_OFF_CHARGING_BOOT)
			|| (BMT_status.g_platform_boot_mode == KERNEL_POWER_OFF_CHARGING_BOOT))
		BMT_status.bat_task_timer = BAT_TASK_POWEROFF_PERIOD;
	else
		BMT_status.bat_task_timer = BAT_TASK_DEFAULT_PERIOD;

	wake_lock_init(&chgin_wakelock, WAKE_LOCK_SUSPEND, "chgin wakelock");
	/* Integrate with Android Battery Service */
	ret = power_supply_register(&(dev->dev), &ac_main.psy);
	if (ret) {
		printk("[BAT_probe] power_supply_register AC Fail !!\n");
		return ret;
	}

	ret = power_supply_register(&(dev->dev), &usb_main.psy);
	if (ret) {
		printk("[BAT_probe] power_supply_register USB Fail !!\n");
		return ret;
	}

	ret = power_supply_register(&(dev->dev), &battery_main.psy);
	if (ret) {
		printk("[BAT_probe] power_supply_register Battery Fail !!\n");
		return ret;
	}
	set_usb_cooling_listener(&usb_temp_listener);

	ret = device_create_file(&(dev->dev), &dev_attr_ADC_Charger_Voltage);
	ret = device_create_file(&(dev->dev), &dev_attr_board_temp);
	ret = device_create_file(&(dev->dev), &dev_attr_limit_fastcharging);
	meizu_sysfslink_register(&(dev->dev));

	/* battery kernel thread for 10s check and charger in/out event */
	alarm_init(&battery_kthread_timer, ALARM_BOOTTIME, battery_kthread_hrtimer_func);
	kthread_run(bat_thread_kthread, NULL, "bat_thread_kthread");
	printk("[battery_probe] bat_thread_kthread Done\n");

	if (chr_det == true) {
		wake_up_bat();
	}
	g_bat_init_flag = KAL_TRUE;
	return 0;
}

static int battery_remove(struct platform_device *dev)
{
	meizu_sysfslink_unregister(&(dev->dev));
	return 0;
}

static void battery_shutdown(struct platform_device *dev)
{
}

static int battery_pm_suspend(struct device *device)
{
	int ret = 0;
	struct platform_device *pdev = to_platform_device(device);
	ktime_t ktime = ktime_set(1, 0);
	BUG_ON(pdev == NULL);

	if (BMT_status.charger_exist == KAL_FALSE) {
		BMT_status.bat_task_timer = BAT_TASK_SUSPEND_PERIOD;
		ktime = ktime_set(BMT_status.bat_task_timer, 0);
		alarm_start_relative(&battery_kthread_timer, ktime);
	}
	return ret;
}

static int battery_pm_resume(struct device *device)
{
	int ret = 0;
	struct platform_device *pdev = to_platform_device(device);
	BUG_ON(pdev == NULL);

	if (BMT_status.charger_exist == KAL_FALSE) {
		BMT_status.bat_task_timer = BAT_TASK_DEFAULT_PERIOD;
		wake_up_bat();
	}
	return ret;
}

struct dev_pm_ops battery_pm_ops = {
	.suspend = battery_pm_suspend,
	.resume = battery_pm_resume,
};

struct platform_device battery_device = {
    .name   = "battery",
    .id        = -1,
};

static struct platform_driver battery_driver = {
	.probe = battery_probe,
	.remove = battery_remove,
	.shutdown = battery_shutdown,
	.driver = {
		.name = "battery",
		.pm = &battery_pm_ops,
	},
};

static int __init battery_init(void)
{
	int ret;

	ret = platform_device_register(&battery_device);
	if (ret) {
		printk("****[battery_device] Unable to device register(%d)\n", ret);
		return ret;
	}

	ret = platform_driver_register(&battery_driver);
	if (ret) {
		printk("****[battery_driver] Unable to register driver (%d)\n", ret);
		return ret;
	}

	return 0;
}

static void __exit battery_exit(void)
{
}

module_init(battery_init);
module_exit(battery_exit);

MODULE_AUTHOR("Oscar Liu");
MODULE_DESCRIPTION("Battery Device Driver");
MODULE_LICENSE("GPL");
