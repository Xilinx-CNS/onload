/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2011-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/hwmon.h>
#include <linux/stat.h>

#include "net_driver.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "nic.h"

#define EFX_HWMON_TYPES_COUNT	hwmon_pwm

static const char *const efx_hwmon_unit[EFX_HWMON_TYPES_COUNT] = {
	[hwmon_temp]  = " degC",
	[hwmon_fan]   = " rpm", /* though nonsense for a heatsink */
	[hwmon_in]    = " mV",
	[hwmon_curr]  = " mA",
	[hwmon_power] = " W",
};

enum efx_hwmon_attribute {
	EFX_HWMON_INPUT,
	EFX_HWMON_MIN,
	EFX_HWMON_MAX,
	EFX_HWMON_CRIT,
	EFX_HWMON_ALARM,
	EFX_HWMON_LABEL,
	EFX_HWMON_NAME
};

#define EFX_HWMON_ATTRIBUTE_COUNT	(EFX_HWMON_NAME + 1)

static const struct {
	const char *label;
	enum hwmon_sensor_types hwmon_type;
	int port;
} efx_mcdi_sensor_type[] = {
#define SENSOR(name, label, hwmon_type, port)				\
	[MC_CMD_SENSOR_##name] = { label, hwmon_ ## hwmon_type, port }
	SENSOR(CONTROLLER_TEMP,		"Controller board temp.",   temp, -1),
	SENSOR(PHY_COMMON_TEMP,		"PHY temp.",		    temp, -1),
	SENSOR(CONTROLLER_COOLING,	"Controller heat sink",	    fan,  -1),
	SENSOR(PHY0_TEMP,		"PHY temp.",		    temp,  0),
	SENSOR(PHY0_COOLING,		"PHY heat sink",	    fan,   0),
	SENSOR(PHY1_TEMP,		"PHY temp.",		    temp,  1),
	SENSOR(PHY1_COOLING,		"PHY heat sink",	    fan,   1),
	SENSOR(IN_1V0,			"1.0V supply",		    in,   -1),
	SENSOR(IN_1V2,			"1.2V supply",		    in,   -1),
	SENSOR(IN_1V8,			"1.8V supply",		    in,   -1),
	SENSOR(IN_2V5,			"2.5V supply",		    in,   -1),
	SENSOR(IN_3V3,			"3.3V supply",		    in,   -1),
	SENSOR(IN_12V0,			"12.0V supply",		    in,   -1),
	SENSOR(IN_1V2A,			"1.2V analogue supply",	    in,   -1),
	SENSOR(IN_VREF,			"Ref. voltage",		    in,   -1),
	SENSOR(OUT_VAOE,		"AOE FPGA supply",	    in,   -1),
	SENSOR(AOE_TEMP,		"AOE FPGA temp.",	    temp, -1),
	SENSOR(PSU_AOE_TEMP,		"AOE regulator temp.",	    temp, -1),
	SENSOR(PSU_TEMP,		"Controller regulator temp.",
								    temp, -1),
	SENSOR(FAN_0,			"Fan 0",		    fan,  -1),
	SENSOR(FAN_1,			"Fan 1",		    fan,  -1),
	SENSOR(FAN_2,			"Fan 2",		    fan,  -1),
	SENSOR(FAN_3,			"Fan 3",		    fan,  -1),
	SENSOR(FAN_4,			"Fan 4",		    fan,  -1),
	SENSOR(IN_VAOE,			"AOE input supply",	    in,   -1),
	SENSOR(OUT_IAOE,		"AOE output current",	    curr, -1),
	SENSOR(IN_IAOE,			"AOE input current",	    curr, -1),
	SENSOR(NIC_POWER,		"Board power use",	    power,-1),
	SENSOR(IN_0V9,			"0.9V supply",		    in,   -1),
	SENSOR(IN_I0V9,			"0.9V supply current",	    curr, -1),
	SENSOR(IN_I1V2,			"1.2V supply current",	    curr, -1),
	SENSOR(IN_0V9_ADC,		"0.9V supply (ext. ADC)",   in,   -1),
	SENSOR(CONTROLLER_2_TEMP,	"Controller board temp. 2", temp, -1),
	SENSOR(VREG_INTERNAL_TEMP,	"Regulator die temp.",	    temp, -1),
	SENSOR(VREG_0V9_TEMP,		"0.9V regulator temp.",     temp, -1),
	SENSOR(VREG_1V2_TEMP,		"1.2V regulator temp.",     temp, -1),
	SENSOR(CONTROLLER_VPTAT,
			      "Controller PTAT voltage (int. ADC)", in,   -1),
	SENSOR(CONTROLLER_INTERNAL_TEMP,
				 "Controller die temp. (int. ADC)", temp, -1),
	SENSOR(CONTROLLER_VPTAT_EXTADC,
			      "Controller PTAT voltage (ext. ADC)", in,   -1),
	SENSOR(CONTROLLER_INTERNAL_TEMP_EXTADC,
				 "Controller die temp. (ext. ADC)", temp, -1),
	SENSOR(AMBIENT_TEMP,		"Ambient temp.",	    temp, -1),
	SENSOR(AIRFLOW,			"Air flow raw",		    in,   -1),
	SENSOR(VDD08D_VSS08D_CSR,	"0.9V die (int. ADC)",	    in,   -1),
	SENSOR(VDD08D_VSS08D_CSR_EXTADC, "0.9V die (ext. ADC)",	    in,   -1),
	SENSOR(HOTPOINT_TEMP,  "Controller board temp. (hotpoint)", temp, -1),
	SENSOR(PHY_POWER_PORT0,		"PHY overcurrent",	    fan,   0),
	SENSOR(PHY_POWER_PORT1,		"PHY overcurrent",	    fan,   1),
	SENSOR(MUM_VCC,			"MUM Vcc",		    in,   -1),
	SENSOR(IN_0V9_A,		"0.9V phase A supply",	    in,   -1),
	SENSOR(IN_I0V9_A,
				     "0.9V phase A supply current", curr, -1),
	SENSOR(VREG_0V9_A_TEMP,
				    "0.9V phase A regulator temp.", temp, -1),
	SENSOR(IN_0V9_B,	        "0.9V phase B supply",	    in,   -1),
	SENSOR(IN_I0V9_B,
				     "0.9V phase B supply current", curr, -1),
	SENSOR(VREG_0V9_B_TEMP,
				    "0.9V phase B regulator temp.", temp, -1),
	SENSOR(CCOM_AVREG_1V2_SUPPLY,
				     "CCOM 1.2V supply (int. ADC)", in,   -1),
	SENSOR(CCOM_AVREG_1V2_SUPPLY_EXTADC,
				     "CCOM 1.2V supply (ext. ADC)", in,   -1),
	SENSOR(CCOM_AVREG_1V8_SUPPLY,
				     "CCOM 1.8V supply (int. ADC)", in,   -1),
	SENSOR(CCOM_AVREG_1V8_SUPPLY_EXTADC,
				     "CCOM 1.8V supply (ext. ADC)", in,   -1),
	SENSOR(CONTROLLER_RTS,		"CCOM RTS temp.",	    temp, -1),
	SENSOR(CONTROLLER_MASTER_VPTAT, "Master die int. temp.",    in,   -1),
	SENSOR(CONTROLLER_MASTER_INTERNAL_TEMP,
					   "Master die int. temp.", temp, -1),
	SENSOR(CONTROLLER_MASTER_VPTAT_EXTADC,
				"Master die int. temp. (ext. ADC)", in,   -1),
	SENSOR(CONTROLLER_MASTER_INTERNAL_TEMP_EXTADC,
				"Master die int. temp. (ext. ADC)", temp, -1),
	SENSOR(CONTROLLER_SLAVE_VPTAT,	"Slave die int. temp.",	    in,   -1),
	SENSOR(CONTROLLER_SLAVE_INTERNAL_TEMP,
					    "Slave die int. temp.", temp, -1),
	SENSOR(CONTROLLER_SLAVE_VPTAT_EXTADC,
				 "Slave die int. temp. (ext. ADC)", in,   -1),
	SENSOR(CONTROLLER_SLAVE_INTERNAL_TEMP_EXTADC,
				 "Slave die int. temp. (ext. ADC)", temp, -1),
	SENSOR(SODIMM_VOUT,		"SODIMM supply.",	    in,   -1),
	SENSOR(SODIMM_0_TEMP,		"SODIMM 0 temp.",	    temp, -1),
	SENSOR(SODIMM_1_TEMP,		"SODIMM 1 temp.",	    temp, -1),
	SENSOR(PHY0_VCC,		"PHY0 supply.",		    in,   -1),
	SENSOR(PHY1_VCC,		"PHY1 supply.",		    in,   -1),
	SENSOR(CONTROLLER_TDIODE_TEMP,
				   "Controller die (TDIODE) temp.", temp, -1),
	SENSOR(BOARD_FRONT_TEMP,	"Board front temp.",	    temp, -1),
	SENSOR(BOARD_BACK_TEMP,		"Board back temp.",	    temp, -1),
	SENSOR(IN_I1V8,			"1.8V supply current",	    curr, -1),
	SENSOR(IN_I2V5,			"2.5V supply current",	    curr, -1),
	SENSOR(IN_I3V3,			"3.3V supply current",	    curr, -1),
	SENSOR(IN_I12V0,		"12V supply current",	    curr, -1),
	SENSOR(IN_1V3,			"1.3V supply",		    in,   -1),
	SENSOR(IN_I1V3,			"1.3V supply current",	    curr, -1),
#undef SENSOR
};

static const char *const sensor_status_names[] = {
	[MC_CMD_SENSOR_STATE_OK] = "OK",
	[MC_CMD_SENSOR_STATE_WARNING] = "Warning",
	[MC_CMD_SENSOR_STATE_FATAL] = "Fatal",
	[MC_CMD_SENSOR_STATE_BROKEN] = "Device failure",
	[MC_CMD_SENSOR_STATE_NO_READING] = "No reading",
};

void efx_mcdi_sensor_event(struct efx_nic *efx, efx_qword_t *ev)
{
	unsigned int type, state, value;
	enum hwmon_sensor_types hwmon_type = hwmon_chip;
	const char *name = NULL, *state_txt, *unit;
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);

	type = EFX_QWORD_FIELD(*ev, MCDI_EVENT_SENSOREVT_MONITOR);
	state = EFX_QWORD_FIELD(*ev, MCDI_EVENT_SENSOREVT_STATE);
	value = EFX_QWORD_FIELD(*ev, MCDI_EVENT_SENSOREVT_VALUE);

	/* Deal gracefully with the board having more drivers than we
	 * know about, but do not expect new sensor states. */
	if (type < ARRAY_SIZE(efx_mcdi_sensor_type)) {
		name = efx_mcdi_sensor_type[type].label;
		hwmon_type = efx_mcdi_sensor_type[type].hwmon_type;
	}
	if (!name)
		name = "No sensor name available";
	EFX_WARN_ON_PARANOID(state >= ARRAY_SIZE(sensor_status_names));
	state_txt = sensor_status_names[state];
	EFX_WARN_ON_PARANOID(hwmon_type >= EFX_HWMON_TYPES_COUNT);
	unit = efx_hwmon_unit[hwmon_type];
	if (!unit)
		unit = "";

	switch (state) {
	case MC_CMD_SENSOR_STATE_OK:
		if (__ratelimit(&rs))
			netif_info(efx, hw, efx->net_dev,
				   "Sensor %d (%s) reports condition '%s' for value %d%s\n",
				   type, name, state_txt, value, unit);
		break;
	case MC_CMD_SENSOR_STATE_WARNING:
		if (__ratelimit(&rs))
			netif_warn(efx, hw, efx->net_dev,
				   "Sensor %d (%s) reports condition '%s' for value %d%s\n",
				   type, name, state_txt, value, unit);
		break;
	default:
		netif_err(efx, hw, efx->net_dev,
			  "Sensor %d (%s) reports condition '%s' for value %d%s\n",
			  type, name, state_txt, value, unit);
		break;
	}
}

#ifdef CONFIG_SFC_MCDI_MON

struct efx_mcdi_mon_attribute {
	struct device_attribute dev_attr;
	unsigned int index;
	unsigned int type;
	enum hwmon_sensor_types hwmon_type;
	unsigned int limit_value;
	enum efx_hwmon_attribute hwmon_attribute;
	u8 file_index;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_HWMON_DEVICE_REGISTER_WITH_INFO)
	char name[15];
#endif
};

static int efx_mcdi_mon_update(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_READ_SENSORS_EXT_IN_LEN);
	int rc;

	MCDI_SET_QWORD(inbuf, READ_SENSORS_EXT_IN_DMA_ADDR,
		       hwmon->dma_buf.dma_addr);
	MCDI_SET_DWORD(inbuf, READ_SENSORS_EXT_IN_LENGTH, hwmon->dma_buf.len);

	rc = efx_mcdi_rpc(efx, MC_CMD_READ_SENSORS,
			  inbuf, sizeof(inbuf), NULL, 0, NULL);
	if (rc == 0)
		hwmon->last_update = jiffies;
	return rc;
}

static int efx_mcdi_mon_get_entry(struct device *dev, unsigned int index,
				  efx_dword_t *entry)
{
	struct efx_nic *efx = dev_get_drvdata(dev);
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	int rc;

	BUILD_BUG_ON(MC_CMD_READ_SENSORS_OUT_LEN != 0);

	mutex_lock(&hwmon->update_lock);

	/* Use cached value if last update was < 1 s ago */
	if (time_before(jiffies, hwmon->last_update + HZ))
		rc = 0;
	else
		rc = efx_mcdi_mon_update(efx);

	/* Copy out the requested entry */
	*entry = ((efx_dword_t *)hwmon->dma_buf.addr)[index];

	mutex_unlock(&hwmon->update_lock);

	return rc;
}

static int efx_mcdi_mon_get_value(struct device *dev, unsigned int index,
				  enum hwmon_sensor_types hwmon_type,
				  unsigned int *value)
{
	efx_dword_t entry;
	unsigned int state;
	int rc;

	rc = efx_mcdi_mon_get_entry(dev, index, &entry);
	if (rc)
		return rc;

	state = EFX_DWORD_FIELD(entry, MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_STATE);
	if (state == MC_CMD_SENSOR_STATE_NO_READING)
		return -EBUSY;

	*value = EFX_DWORD_FIELD(entry, MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_VALUE);

	switch (hwmon_type) {
	case hwmon_temp:
		/* Convert temperature from degrees to milli-degrees Celsius */
		*value *= 1000;
		break;
	case hwmon_power:
		/* Convert power from watts to microwatts */
		*value *= 1000000;
		break;
	default:
		/* No conversion needed */
		break;
	}
	return 0;
}

static unsigned int
efx_mcdi_mon_get_limit(struct efx_mcdi_mon_attribute *mon_attr)
{
	unsigned int value;

	value = mon_attr->limit_value;

	switch (mon_attr->hwmon_type) {
	case hwmon_temp:
		/* Convert temperature from degrees to milli-degrees Celsius */
		value *= 1000;
		break;
	case hwmon_power:
		/* Convert power from watts to microwatts */
		value *= 1000000;
		break;
	default:
		/* No conversion needed */
		break;
	}
	return value;
}

static int efx_mcdi_mon_get_state(struct device *dev, unsigned int index,
				  unsigned int *value)
{
	efx_dword_t entry;
	int rc;

	rc = efx_mcdi_mon_get_entry(dev, index, &entry);
	if (rc)
		return rc;

	return EFX_DWORD_FIELD(entry, MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_STATE);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_HWMON_DEVICE_REGISTER_WITH_INFO)
static ssize_t efx_mcdi_mon_show_name(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return sprintf(buf, "%s\n", KBUILD_MODNAME);
}

static ssize_t efx_mcdi_mon_show_value(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	unsigned int value = 0;
	int rc = efx_mcdi_mon_get_value(dev, mon_attr->index,
					mon_attr->hwmon_type, &value);

	if (rc)
		return rc;
	return sprintf(buf, "%u\n", value);
}

static ssize_t efx_mcdi_mon_show_limit(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	unsigned int value = efx_mcdi_mon_get_limit(mon_attr);

	return sprintf(buf, "%u\n", value);
}

static ssize_t efx_mcdi_mon_show_alarm(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	int state = 0;
	int rc;

	rc = efx_mcdi_mon_get_state(dev, mon_attr->index, &state);
	if (rc)
		return rc;

	return sprintf(buf, "%d\n", state != MC_CMD_SENSOR_STATE_OK);
}

static ssize_t efx_mcdi_mon_show_label(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	return sprintf(buf, "%s\n",
		       efx_mcdi_sensor_type[mon_attr->type].label);
}

static int efx_mcdi_mon_create_files(struct device *dev,
				     struct efx_mcdi_mon *hwmon)
{
	int rc = 0, i;

	for (i=0; i < hwmon->n_attrs; i++) {
		struct efx_mcdi_mon_attribute *attr = &hwmon->attrs[i];
		const char *hwmon_prefix;

		sysfs_attr_init(&attr->dev_attr.attr);
		attr->dev_attr.attr.mode = S_IRUGO;

		switch (attr->hwmon_type) {
		case hwmon_temp:
			hwmon_prefix = "temp";
			break;
		case hwmon_fan:
			/* This is likely to be a heatsink, but there
			 * is no convention for representing cooling
			 * devices other than fans.
			 */
			hwmon_prefix = "fan";
			break;
		case hwmon_in:
			hwmon_prefix = "in";
			break;
		case hwmon_curr:
			hwmon_prefix = "curr";
			break;
		case hwmon_power:
			hwmon_prefix = "power";
			break;
		case hwmon_chip:
			continue;
		default:
			dev_warn(dev, "Unknown HW monitor type %d\n",
				 attr->hwmon_type);
			continue;
		}

		switch (attr->hwmon_attribute) {
		case EFX_HWMON_INPUT:
			attr->dev_attr.show = efx_mcdi_mon_show_value;
			snprintf(attr->name, sizeof(attr->name), "%s%hhu_input",
				 hwmon_prefix, attr->file_index);
			break;
		case EFX_HWMON_MIN:
			attr->dev_attr.show = efx_mcdi_mon_show_limit;
			snprintf(attr->name, sizeof(attr->name), "%s%hhu_min",
				 hwmon_prefix, attr->file_index);
			break;
		case EFX_HWMON_MAX:
			attr->dev_attr.show = efx_mcdi_mon_show_limit;
			snprintf(attr->name, sizeof(attr->name), "%s%hhu_max",
				 hwmon_prefix, attr->file_index);
			break;
		case EFX_HWMON_CRIT:
			attr->dev_attr.show = efx_mcdi_mon_show_limit;
			snprintf(attr->name, sizeof(attr->name), "%s%hhu_crit",
				 hwmon_prefix, attr->file_index);
			break;
		case EFX_HWMON_ALARM:
			attr->dev_attr.show = efx_mcdi_mon_show_alarm;
			snprintf(attr->name, sizeof(attr->name), "%s%hhu_alarm",
				 hwmon_prefix, attr->file_index);
			break;
		case EFX_HWMON_LABEL:
			attr->dev_attr.show = efx_mcdi_mon_show_label;
			snprintf(attr->name, sizeof(attr->name), "%s%hhu_label",
				 hwmon_prefix, attr->file_index);
			break;
		case EFX_HWMON_NAME:
			attr->dev_attr.show = efx_mcdi_mon_show_name;
			snprintf(attr->name, sizeof(attr->name), "name");
			break;
		default:
			dev_warn(dev, "Unknown HW monitor attribute %d\n",
				 attr->hwmon_attribute);
			continue;
		}
		attr->dev_attr.attr.name = attr->name;
		rc = device_create_file(dev, &attr->dev_attr);
		if (rc) {
			attr->name[0] = '\0';
			break;
		}
	}
	return rc;
}

static void efx_mcdi_mon_remove_files(struct device *dev,
				      struct efx_mcdi_mon *hwmon)
{
	unsigned int i;

	for (i = 0; (i < hwmon->n_attrs) && hwmon->attrs[i].name[0]; i++)
		device_remove_file(dev, &hwmon->attrs[i].dev_attr);
}

#define efx_hwmon_chip_info_p	NULL
#else
/* These defines must match with the efx_attrib_map array below. */
#define EFX_HWMON_TEMP_CONFIG	(HWMON_T_INPUT | HWMON_T_MIN | HWMON_T_MAX | \
				 HWMON_T_CRIT | HWMON_T_ALARM | HWMON_T_LABEL)
#define EFX_HWMON_IN_CONFIG	(HWMON_I_INPUT | HWMON_I_MIN | HWMON_I_MAX | \
				 HWMON_I_CRIT | HWMON_I_ALARM | HWMON_I_LABEL)
#define EFX_HWMON_CURR_CONFIG	(HWMON_C_INPUT | HWMON_C_MIN | HWMON_C_MAX | \
				 HWMON_C_CRIT | HWMON_C_ALARM | HWMON_C_LABEL)
#define EFX_HWMON_POWER_CONFIG	(HWMON_P_INPUT | HWMON_P_LABEL)
#define EFX_HWMON_FAN_CONFIG	(HWMON_F_ALARM | HWMON_F_LABEL)

static const u32
efx_attrib_map[EFX_HWMON_TYPES_COUNT][EFX_HWMON_ATTRIBUTE_COUNT] = {
	[hwmon_temp] = { HWMON_T_INPUT, HWMON_T_MIN, HWMON_T_MAX, HWMON_T_CRIT,
			 HWMON_T_ALARM, HWMON_T_LABEL, 0 },
	[hwmon_in] = { HWMON_I_INPUT, HWMON_I_MIN, HWMON_I_MAX, HWMON_I_CRIT,
			 HWMON_I_ALARM, HWMON_I_LABEL, 0 },
	[hwmon_curr] = { HWMON_C_INPUT, HWMON_C_MIN, HWMON_C_MAX, HWMON_C_CRIT,
			 HWMON_C_ALARM, HWMON_C_LABEL, 0 },
	[hwmon_power] = { HWMON_P_INPUT, 0, 0, 0, 0, HWMON_P_LABEL, 0 },
	[hwmon_fan] = { 0, 0, 0, 0, HWMON_F_ALARM, HWMON_F_LABEL, 0 },
};

static int efx_mcdi_mon_create_files(struct device *dev,
				     struct efx_mcdi_mon *hwmon)
{
	return 0;
}

static void efx_mcdi_mon_remove_files(struct device *dev,
				      struct efx_mcdi_mon *hwmon)
{
}

static struct efx_mcdi_mon_attribute *
efx_hwmon_get_attribute(const struct efx_nic *efx,
			enum hwmon_sensor_types type, u32 attr, int channel)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon((struct efx_nic *) efx);
	struct efx_mcdi_mon_attribute *attribute;
	enum efx_hwmon_attribute hwmon_attribute;
	int	i;

	if (type > EFX_HWMON_TYPES_COUNT)
		return NULL;

	for (i=0; i < EFX_HWMON_ATTRIBUTE_COUNT; i++) {
		if (efx_attrib_map[type][i] == BIT(attr)) {
			hwmon_attribute = i;
			break;
		}
	}
	if (i ==  EFX_HWMON_ATTRIBUTE_COUNT)
		return NULL;

	for (i=0; i < hwmon->n_attrs; i++) {
		attribute = &hwmon->attrs[i];
		if ((attribute->hwmon_type == type) &&
		    (attribute->hwmon_attribute == hwmon_attribute) &&
		    (attribute->file_index == channel))
			return attribute;
	}
	return NULL;
}

static int efx_hwmon_read(struct device *dev,
			  enum hwmon_sensor_types type,
			  u32 attr, int channel, long *val)
{
	const struct efx_nic *efx = dev_get_drvdata(dev);
	struct efx_mcdi_mon_attribute *mon_attr =
		efx_hwmon_get_attribute(efx, type, attr, channel);
	int	rc;
	unsigned int value = 0;

	*val = 0;
	if (!mon_attr)
		return -EOPNOTSUPP;

	switch (mon_attr->hwmon_attribute) {
	case EFX_HWMON_INPUT:
		rc = efx_mcdi_mon_get_value(dev, mon_attr->index,
					    mon_attr->hwmon_type, &value);
		if (rc < 0)
			return rc;
		break;
	case EFX_HWMON_MIN:
	case EFX_HWMON_MAX:
	case EFX_HWMON_CRIT:
		value = efx_mcdi_mon_get_limit(mon_attr);
		break;
	case EFX_HWMON_ALARM:
		rc = efx_mcdi_mon_get_state(dev, mon_attr->index, &value);
		if (rc)
			return rc;
		value = (value != MC_CMD_SENSOR_STATE_OK);
		break;
#ifndef EFX_HAVE_HWMON_READ_STRING
	case EFX_HWMON_LABEL:
		return -EOPNOTSUPP;
#endif
	default:
		WARN_ONCE(1, "Unhandled HW sensor read\n");
		return -EOPNOTSUPP;
	}
	*val = value;
	return 0;
}

#ifdef EFX_HAVE_HWMON_READ_STRING
static int efx_hwmon_read_string(struct device *dev,
				 enum hwmon_sensor_types type,
				 u32 attr, int channel,
#ifdef EFX_HAVE_HWMON_READ_STRING_CONST
				 const char **str
#else
				 char **str
#endif
				)
{
	const struct efx_nic *efx = dev_get_drvdata(dev);
	struct efx_mcdi_mon_attribute *mon_attr =
		efx_hwmon_get_attribute(efx, type, attr, channel);

	if (mon_attr)
		*str = (char *) efx_mcdi_sensor_type[mon_attr->type].label;
	return(!mon_attr);
}
#endif

static umode_t efx_hwmon_is_visible(const void *data,
				    enum hwmon_sensor_types type,
				    u32 attr, int channel)
{
	const struct efx_nic *efx = data;
	struct efx_mcdi_mon_attribute *mon_attr = efx_hwmon_get_attribute(
		efx, type, attr, channel);

	if (mon_attr)
		return S_IRUGO;
	else
		return 0;
}

static const u32 efx_temp_config[] = {
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	EFX_HWMON_TEMP_CONFIG,
	0
};

static const struct hwmon_channel_info efx_temp = {
	.type = hwmon_temp,
	.config = efx_temp_config,
};

static const u32 efx_in_config[] = {
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
	0
};

static const struct hwmon_channel_info efx_in = {
	.type = hwmon_in,
	.config = efx_in_config,
};

static const u32 efx_curr_config[] = {
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	0
};

static const struct hwmon_channel_info efx_curr = {
	.type = hwmon_curr,
	.config = efx_curr_config,
};

static const u32 efx_power_config[] = {
	EFX_HWMON_POWER_CONFIG,
	0
};

static const struct hwmon_channel_info efx_power = {
	.type = hwmon_power,
	.config = efx_power_config,
};

static const u32 efx_fan_config[] = {
	EFX_HWMON_FAN_CONFIG,
	EFX_HWMON_FAN_CONFIG,
	EFX_HWMON_FAN_CONFIG,
	EFX_HWMON_FAN_CONFIG,
	0
};

static const struct hwmon_channel_info efx_fan = {
	.type = hwmon_fan,
	.config = efx_fan_config,
};

static const struct hwmon_channel_info *efx_hwmon_info[] = {
	&efx_temp,
	&efx_in,
	&efx_curr,
	&efx_power,
	&efx_fan,
	NULL
};

static const struct hwmon_ops efx_hwmon_ops = {
	.is_visible = efx_hwmon_is_visible,
	.read = efx_hwmon_read,
#if defined(EFX_HAVE_HWMON_READ_STRING)
	.read_string = efx_hwmon_read_string,
#endif
};

static const struct hwmon_chip_info efx_hwmon_chip_info = {
	.ops = &efx_hwmon_ops,
	.info = efx_hwmon_info,
};

#define efx_hwmon_chip_info_p	&efx_hwmon_chip_info
#endif

static void
efx_mcdi_mon_add_attr(struct efx_nic *efx,
		      unsigned int index, unsigned int type,
		      unsigned int limit_value, u8 file_index,
		      enum efx_hwmon_attribute attribute)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	struct efx_mcdi_mon_attribute *attr = &hwmon->attrs[hwmon->n_attrs];

	attr->index = index;
	attr->type = type;
	if (type < ARRAY_SIZE(efx_mcdi_sensor_type))
		attr->hwmon_type = efx_mcdi_sensor_type[type].hwmon_type;
	else
		attr->hwmon_type = hwmon_chip;
	attr->limit_value = limit_value;
	attr->file_index = file_index;
	attr->hwmon_attribute = attribute;
	++hwmon->n_attrs;
}

int efx_mcdi_mon_probe(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	u8 n_temp = 0, n_cool = 0, n_in = 0, n_curr = 0, n_power = 0;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SENSOR_INFO_EXT_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_SENSOR_INFO_OUT_LENMAX);
	unsigned int n_pages, n_sensors, n_attrs, page;
	size_t outlen;
	u32 mask;
	int rc, i, j, type;

	/* Do not probe twice */
	if (hwmon->dma_buf.addr)
		return 0;

	/* Find out how many sensors are present */
	n_sensors = 0;
	page = 0;
	do {
		MCDI_SET_DWORD(inbuf, SENSOR_INFO_EXT_IN_PAGE, page);

		rc = efx_mcdi_rpc(efx, MC_CMD_SENSOR_INFO, inbuf, sizeof(inbuf),
				  outbuf, sizeof(outbuf), &outlen);
		if (rc)
			return rc;
		if (outlen < MC_CMD_SENSOR_INFO_OUT_LENMIN)
			return -EIO;

		mask = MCDI_DWORD(outbuf, SENSOR_INFO_OUT_MASK);
		n_sensors += hweight32(mask & ~(1 << MC_CMD_SENSOR_PAGE0_NEXT));
		++page;
	} while (mask & (1 << MC_CMD_SENSOR_PAGE0_NEXT));
	n_pages = page;

	/* Don't create a device if there are none */
	if (n_sensors == 0)
		return 0;

	rc = efx_nic_alloc_buffer(
		efx, &hwmon->dma_buf,
		n_sensors * MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_LEN,
		GFP_KERNEL);
	if (rc)
		return rc;

	mutex_init(&hwmon->update_lock);
	efx_mcdi_mon_update(efx);

	/* Allocate space for the maximum possible number of
	 * attributes for this set of sensors: name of the driver plus
	 * value, min, max, crit, alarm and label for each sensor.
	 */
	n_attrs = 1 + 6 * n_sensors;
	hwmon->attrs = kcalloc(n_attrs, sizeof(*hwmon->attrs), GFP_KERNEL);
	if (!hwmon->attrs) {
		rc = -ENOMEM;
		goto fail;
	}

	efx_mcdi_mon_add_attr(efx, 0, 0, 0, 0, EFX_HWMON_NAME);

	for (i = 0, j = -1, type = -1; ; i++) {
		enum hwmon_sensor_types hwmon_type;
		u16 min1, max1, min2, max2;
		u8 file_index = 0;

		/* Find next sensor type or exit if there is none */
		do {
			type++;

			if ((type % 32) == 0) {
				page = type / 32;
				j = -1;
				if (page == n_pages)
					goto do_register;

				MCDI_SET_DWORD(inbuf, SENSOR_INFO_EXT_IN_PAGE,
					       page);
				rc = efx_mcdi_rpc(efx, MC_CMD_SENSOR_INFO,
						  inbuf, sizeof(inbuf),
						  outbuf, sizeof(outbuf),
						  &outlen);
				if (rc)
					goto fail;
				if (outlen < MC_CMD_SENSOR_INFO_OUT_LENMIN) {
					rc = -EIO;
					goto fail;
				}

				mask = (MCDI_DWORD(outbuf,
						   SENSOR_INFO_OUT_MASK) &
					~(1 << MC_CMD_SENSOR_PAGE0_NEXT));

				/* Check again for short response */
				if (outlen <
				    MC_CMD_SENSOR_INFO_OUT_LEN(hweight32(mask))) {
					rc = -EIO;
					goto fail;
				}
			}
		} while (!(mask & (1 << type % 32)));
		j++;

		if (type < ARRAY_SIZE(efx_mcdi_sensor_type)) {
			hwmon_type = efx_mcdi_sensor_type[type].hwmon_type;

			/* Skip sensors specific to a different port */
			if (hwmon_type != hwmon_chip &&
			    efx_mcdi_sensor_type[type].port >= 0 &&
			    efx_mcdi_sensor_type[type].port !=
			    efx_port_num(efx))
				continue;
		} else {
			hwmon_type = hwmon_chip;
		}

		switch (hwmon_type) {
		case hwmon_temp:
			file_index = ++n_temp; /* 1-based */
			break;
		case hwmon_fan:
			file_index = ++n_cool; /* 1-based */
			break;
		default:
			file_index = n_in++; /* 0-based */
			break;
		case hwmon_curr:
			file_index = ++n_curr; /* 1-based */
			break;
		case hwmon_power:
			file_index = ++n_power; /* 1-based */
			break;
		}

		min1 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, j, MIN1);
		max1 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, j, MAX1);
		min2 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, j, MIN2);
		max2 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, j, MAX2);

		efx_mcdi_mon_add_attr(efx, i, type, 0, file_index,
				      EFX_HWMON_INPUT);

		if (min1 != max1) {
			if (hwmon_type != hwmon_power) {
				efx_mcdi_mon_add_attr(efx, i, type, min1,
						      file_index,
						      EFX_HWMON_MIN);
			}

			efx_mcdi_mon_add_attr(efx, i, type, max1, file_index,
					      EFX_HWMON_MAX);
		}

		if (min2 != max2) {
			/* Assume max2 is critical value.
			 * But we have no good way to expose min2.
			 */
			efx_mcdi_mon_add_attr(efx, i, type, max2,
					      file_index,
					      EFX_HWMON_CRIT);
		}

		efx_mcdi_mon_add_attr(efx, i, type, 0, file_index,
				      EFX_HWMON_ALARM);

		if (type < ARRAY_SIZE(efx_mcdi_sensor_type) &&
		    efx_mcdi_sensor_type[type].label) {
			efx_mcdi_mon_add_attr(efx, i, type, 0, file_index,
					      EFX_HWMON_LABEL);
		}
	}

do_register:
	hwmon->device = hwmon_device_register_with_info(&efx->pci_dev->dev,
							efx->name, efx,
							efx_hwmon_chip_info_p,
							NULL);
	if (IS_ERR(hwmon->device)) {
		rc = PTR_ERR(hwmon->device);
		goto fail;
	}

	rc = efx_mcdi_mon_create_files(&efx->pci_dev->dev, hwmon);
	if (!rc)
		return 0;

fail:
	efx_mcdi_mon_remove(efx);
	return rc;
}

void efx_mcdi_mon_remove(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);

	if (!hwmon)
		return;

	efx_mcdi_mon_remove_files(&efx->pci_dev->dev, hwmon);
	if (!IS_ERR_OR_NULL(hwmon->device))
		hwmon_device_unregister(hwmon->device);
	if (hwmon->attrs)
		kfree(hwmon->attrs);
	hwmon->attrs = NULL;
	efx_nic_free_buffer(efx, &hwmon->dma_buf);
	hwmon->n_attrs = 0;
}

#endif /* CONFIG_SFC_MCDI_MON */
