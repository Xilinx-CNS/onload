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

#define EFX_DYNAMIC_SENSOR_READING_UPDATE_MAX_HANDLES 32
#define EFX_DYNAMIC_SENSOR_INFO_READ_MAX_HANDLES 4

#define       MC_CMD_DYN_SENSOR_LIMIT_LO_WARNING_OFST \
		(MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_LIMITS_OFST + 0)
#define       MC_CMD_DYN_SENSOR_LIMIT_LO_CRITICAL_OFST \
		(MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_LIMITS_OFST + 4)
#define       MC_CMD_DYN_SENSOR_LIMIT_LO_FATAL_OFST \
		(MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_LIMITS_OFST + 8)
#define       MC_CMD_DYN_SENSOR_LIMIT_HI_WARNING_OFST \
		(MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_LIMITS_OFST + 12)
#define       MC_CMD_DYN_SENSOR_LIMIT_HI_CRITICAL_OFST \
		(MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_LIMITS_OFST + 16)
#define       MC_CMD_DYN_SENSOR_LIMIT_HI_FATAL_OFST \
		(MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_LIMITS_OFST + 20)

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

struct efx_mcdi_hwmon_info {
	const char *label;
	enum hwmon_sensor_types hwmon_type;
	int port;
};

static const struct efx_mcdi_hwmon_info efx_mcdi_sensor_type[] = {
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

struct efx_mcdi_mon_attribute {
	struct device_attribute dev_attr;
	unsigned int index;
	unsigned int type;
	enum hwmon_sensor_types hwmon_type;
	unsigned int limit_value;
	enum efx_hwmon_attribute hwmon_attribute;
	u8 file_index;
	bool is_dynamic;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_HWMON_DEVICE_REGISTER_WITH_INFO)
	char name[15];
#endif
};

#ifdef CONFIG_SFC_MCDI_MON

void efx_mcdi_sensor_event(struct efx_nic *efx, efx_qword_t *ev)
{
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	enum hwmon_sensor_types hwmon_type = hwmon_chip;
	const char *name = NULL, *state_txt, *unit;
	unsigned int type, state, value;

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

enum efx_sensor_limits {
	EFX_SENSOR_LIMIT_WARNING_LO,
	EFX_SENSOR_LIMIT_CRITICAL_LO,
	EFX_SENSOR_LIMIT_FATAL_LO,
	EFX_SENSOR_LIMIT_WARNING_HI,
	EFX_SENSOR_LIMIT_CRITICAL_HI,
	EFX_SENSOR_LIMIT_FATAL_HI,
	EFX_SENSOR_LIMITS
};

/*
 * struct efx_dynamic_sensor_description - dynamic sensor description
 * @name: name of the sensor
 * @idx: sensor index in the host driver maintained list
 * @handle: handle to the sensor
 * @type: type of sensor
 * @limits: limits for the sensor reading
 * @gen_count: generation count corresponding to the description
 * @entry: an entry in rhashtable of dynamic sensors
 */
struct efx_dynamic_sensor_description {
	char name[MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_NAME_LEN];
	unsigned int idx;
	unsigned int handle;
	unsigned int type;
	int limits[EFX_SENSOR_LIMITS];
	unsigned int gen_count;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
	struct rhash_head entry;
#endif
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
const static struct rhashtable_params sensor_entry_params = {
	.key_len     = sizeof(unsigned int),
	.key_offset  = offsetof(struct efx_dynamic_sensor_description, handle),
	.head_offset = offsetof(struct efx_dynamic_sensor_description, entry),
};
#endif

static struct efx_dynamic_sensor_description *
efx_mcdi_get_dynamic_sensor(struct efx_nic *efx, unsigned int handle)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);

	return rhashtable_lookup_fast(&hwmon->sensor_table, &handle,
				      sensor_entry_params);
#else
	return NULL;
#endif
}

static void efx_mcdi_handle_dynamic_sensor_state_change(struct efx_nic *efx,
						 efx_qword_t *ev)
{
	int count = EFX_QWORD_FIELD(*ev, MCDI_EVENT_CONT);
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	struct efx_dynamic_sensor_description *sensor;
	efx_dword_t *sensor_reading_entry;
	const char *state_txt;
	unsigned int handle;
	int state, value;

	mutex_lock(&hwmon->update_lock);
	/* Need to receive event with count = 1 first */
	if (count) {
		handle = EFX_QWORD_FIELD(*ev, MCDI_EVENT_DATA);
		sensor = efx_mcdi_get_dynamic_sensor(efx, handle);
		if (!sensor)
			return;
		sensor_reading_entry =
			MCDI_ARRAY_STRUCT_PTR(((efx_dword_t *)hwmon->dma_buf.addr),
					      DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES,
					      sensor->idx);
		/* save sensor index to handle 2nd event of
		 * DYNAMIC_SENSOR_STATE_CHANGE */
		hwmon->pend_sensor_state_handle = handle;
		state = EFX_QWORD_FIELD(*ev, MCDI_EVENT_SRC);
		EFX_WARN_ON_PARANOID(state >= ARRAY_SIZE(sensor_status_names));
		state_txt = sensor_status_names[state];
		WARN(1, "%s: sensor %s state changed to %s\n", efx->name,
			sensor->name, state_txt);

		MCDI_SET_DWORD(sensor_reading_entry,
			       DYNAMIC_SENSORS_READING_HANDLE,
			       handle);
		MCDI_SET_DWORD(sensor_reading_entry,
			       DYNAMIC_SENSORS_READING_STATE, state);
	} else {
		EFX_WARN_ON_PARANOID(hwmon->pend_sensor_state_handle < 0);
		handle = hwmon->pend_sensor_state_handle;
		sensor = efx_mcdi_get_dynamic_sensor(efx, handle);
		hwmon->pend_sensor_state_handle = -1;
		if (!sensor)
			return;
		sensor_reading_entry =
			MCDI_ARRAY_STRUCT_PTR(((efx_dword_t *)hwmon->dma_buf.addr),
					      DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES,
					      sensor->idx);
		value = EFX_QWORD_FIELD(*ev, MCDI_EVENT_DATA);
		MCDI_SET_DWORD(sensor_reading_entry,
			       DYNAMIC_SENSORS_READING_VALUE, value);
	}
	mutex_unlock(&hwmon->update_lock);
}

void efx_mcdi_dynamic_sensor_event(struct efx_nic *efx, efx_qword_t *ev)
{
	int code = EFX_QWORD_FIELD(*ev, MCDI_EVENT_CODE);

	switch(code) {
	case MCDI_EVENT_CODE_DYNAMIC_SENSORS_STATE_CHANGE:
		efx_mcdi_handle_dynamic_sensor_state_change(efx, ev);
		return;
	case MCDI_EVENT_CODE_DYNAMIC_SENSORS_CHANGE:
		netif_info(efx, drv, efx->net_dev,
			   "CODE_DYNAMIC_SENSORS_CHANGE even unsupported\n");
	}
}

static int
efx_mcdi_dynamic_sensor_list_reading_update(struct efx_nic *efx,
					    unsigned int *handle_list,
					    unsigned int num_handles)
{
	MCDI_DECLARE_BUF(outbuf,
			 MC_CMD_DYNAMIC_SENSORS_GET_READINGS_OUT_LEN(EFX_DYNAMIC_SENSOR_READING_UPDATE_MAX_HANDLES));
	MCDI_DECLARE_BUF(inbuf,
			 MC_CMD_DYNAMIC_SENSORS_GET_READINGS_IN_LEN(EFX_DYNAMIC_SENSOR_READING_UPDATE_MAX_HANDLES));
	struct efx_dynamic_sensor_description *sensor = NULL;
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	efx_dword_t *sensor_reading_entry;
	efx_dword_t *sensor_out_entry;
	unsigned int handle;
	size_t outlen;
	int i, rc = 0;

	for (i = 0; i < num_handles; i++)
		MCDI_SET_ARRAY_DWORD(inbuf,
				     DYNAMIC_SENSORS_GET_READINGS_IN_HANDLES, i,
				     handle_list[i]);
	rc = efx_mcdi_rpc(efx, MC_CMD_DYNAMIC_SENSORS_GET_READINGS, inbuf,
			  MC_CMD_DYNAMIC_SENSORS_GET_READINGS_IN_LEN(i),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	/* outlen determins the number of handles returned if any handles
	 * are dropped by FW */
	if (outlen % MC_CMD_DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES_LEN) {
		WARN_ON(1);
		return -EINVAL;
	}
	i = 0;
	while (outlen) {
		sensor_out_entry =
			MCDI_ARRAY_STRUCT_PTR(outbuf,
					      DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES,
					      i);
		handle = MCDI_DWORD(sensor_out_entry,
				    DYNAMIC_SENSORS_READING_HANDLE);
		sensor = efx_mcdi_get_dynamic_sensor(efx, handle);
		/* check if sensor was dropped */
		if (IS_ERR(sensor)) {
			i++;
			outlen -= MC_CMD_DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES_LEN;
			continue;
		}
		sensor_reading_entry =
			MCDI_ARRAY_STRUCT_PTR(((efx_dword_t *)hwmon->dma_buf.addr),
					      DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES,
					      sensor->idx);
		MCDI_SET_DWORD(sensor_reading_entry,
			       DYNAMIC_SENSORS_READING_HANDLE, handle);
		MCDI_SET_DWORD(sensor_reading_entry,
			       DYNAMIC_SENSORS_READING_VALUE,
			       (MCDI_DWORD(sensor_out_entry,
					  DYNAMIC_SENSORS_READING_VALUE)));
		MCDI_SET_DWORD(sensor_reading_entry,
			       DYNAMIC_SENSORS_READING_STATE,
			       (MCDI_DWORD(sensor_out_entry,
					  DYNAMIC_SENSORS_READING_STATE)));
		netif_dbg(efx, drv, efx->net_dev,
			  "Reading sensor, handle %u, value %u state: %u\n",
			  handle,
			  MCDI_DWORD(sensor_out_entry,
				     DYNAMIC_SENSORS_READING_VALUE),
			  MCDI_DWORD(sensor_out_entry,
				     DYNAMIC_SENSORS_READING_STATE));


		i++;
		outlen -= MC_CMD_DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES_LEN;
	}
	if (rc == 0)
		hwmon->last_update = jiffies;

	return rc;

}

static int efx_mcdi_dynamic_sensor_reading_update(struct efx_nic *efx)
{
	struct efx_dynamic_sensor_description *sensor;
	/* limiting maximum sensors per read to 4 to avoid
	 * -Werror=frame-larger-than=]
	 */
	unsigned int handles[EFX_DYNAMIC_SENSOR_INFO_READ_MAX_HANDLES];
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	unsigned int j, i = 0;
	int rc = 0;

	sensor = (struct efx_dynamic_sensor_description *)hwmon->sensor_list;
	for (j = 0; j < hwmon->n_dynamic_sensors; j++) {
		handles[i] = sensor[j].handle;
		i++;
		if ((i == EFX_DYNAMIC_SENSOR_INFO_READ_MAX_HANDLES) ||
		    (j == (hwmon->n_dynamic_sensors - 1))) {
			rc = efx_mcdi_dynamic_sensor_list_reading_update(efx,
									 handles,
									 i);
			if (!rc)
				i = 0;
			else
				break;
		}
	}

	return rc;
}

static void
efx_mcdi_mon_add_attr(struct efx_nic *efx,
		      unsigned int index, unsigned int type,
		      unsigned int limit_value, u8 file_index,
		      enum efx_hwmon_attribute attribute,
		      bool is_dynamic)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	struct efx_mcdi_mon_attribute *attr = &hwmon->attrs[hwmon->n_attrs];

	attr->index = index;
	attr->type = type;

	if (is_dynamic) {
		/* Conversion between FW types and kernel types */
		if (type == 0)
			attr->hwmon_type = hwmon_in;
		if (type == 1)
			attr->hwmon_type = hwmon_curr;
		if (type == 2)
			attr->hwmon_type = hwmon_power;
		if (type == 3)
			attr->hwmon_type = hwmon_temp;
		if (type == 4)
			attr->hwmon_type = hwmon_fan;
	} else {
		if (type < ARRAY_SIZE(efx_mcdi_sensor_type))
			attr->hwmon_type =
				efx_mcdi_sensor_type[type].hwmon_type;
		else
			attr->hwmon_type = hwmon_chip;
	}

	attr->limit_value = limit_value;
	attr->file_index = file_index;
	attr->hwmon_attribute = attribute;
	attr->is_dynamic = is_dynamic;
	++hwmon->n_attrs;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
static void efx_mcdi_add_dynamic_sensor(struct efx_nic *efx,
					unsigned int handle,
					unsigned int idx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	struct efx_dynamic_sensor_description *sensor;

	sensor = (struct efx_dynamic_sensor_description *)hwmon->sensor_list;
	sensor += idx;
	/* sensor->idx need to stored as this is needed to access sensor
	 * reading data saved
	 */
	sensor->idx = idx;
	sensor->handle = handle;
	rhashtable_lookup_insert_fast(&hwmon->sensor_table,
				      &sensor->entry,
				      sensor_entry_params);
}

static void efx_mcdi_remove_dynamic_sensors(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	struct efx_dynamic_sensor_description *sensor;
	int i = 0;

	sensor = (struct efx_dynamic_sensor_description *)hwmon->sensor_list;
	for(i = 0; i < hwmon->n_dynamic_sensors; i++) {
		rhashtable_remove_fast(&hwmon->sensor_table,
				       &sensor[i].entry,
				       sensor_entry_params);
	}
}

/* This function is assumed to be called only after @has_dynamic_sensors
 * has returned true or DYNAMIC_SENSOR_LIST event received
 */
static int efx_mcdi_read_dynamic_sensor_list(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_DYNAMIC_SENSORS_LIST_OUT_LENMAX);
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	unsigned int n_sensors;
	unsigned int gen_count;
	size_t outlen;
	int rc, i;

	rc = efx_mcdi_rpc(efx, MC_CMD_DYNAMIC_SENSORS_LIST, NULL, 0, outbuf,
			  sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	gen_count = MCDI_DWORD(outbuf, DYNAMIC_SENSORS_LIST_OUT_GENERATION);
	/* check if generation count changed */
	if (gen_count == hwmon->generation_count)
		return 0;
	hwmon->generation_count = gen_count;

	n_sensors = MCDI_DWORD(outbuf, DYNAMIC_SENSORS_LIST_OUT_COUNT);
	if (outlen < MC_CMD_DYNAMIC_SENSORS_LIST_OUT_LEN(n_sensors)) {
		WARN_ON(1);
		return -EINVAL;
	}
	mutex_lock(&hwmon->update_lock);
	efx_mcdi_remove_dynamic_sensors(efx);
	hwmon->n_dynamic_sensors = n_sensors;
	hwmon->sensor_list = krealloc(hwmon->sensor_list,
				      (n_sensors *
				      sizeof(struct efx_dynamic_sensor_description)),
				      GFP_KERNEL);
	if (!hwmon->sensor_list) {
		mutex_unlock(&hwmon->update_lock);
		return -ENOMEM;
	}

	for (i = 0; i < n_sensors; i++) {
		unsigned int handle;

		handle = MCDI_ARRAY_DWORD(outbuf,
					  DYNAMIC_SENSORS_LIST_OUT_HANDLES, i);
		efx_mcdi_add_dynamic_sensor(efx, handle, i);
	}

	mutex_unlock(&hwmon->update_lock);

	return 0;
}
#endif

static int efx_mcdi_read_dynamic_sensor_list_info(struct efx_nic *efx,
						  unsigned int *handle_list,
						  unsigned int num_handles)
{
	MCDI_DECLARE_BUF(outbuf,
			 MC_CMD_DYNAMIC_SENSORS_GET_DESCRIPTIONS_OUT_LEN(EFX_DYNAMIC_SENSOR_INFO_READ_MAX_HANDLES));
	MCDI_DECLARE_BUF(inbuf,
			 MC_CMD_DYNAMIC_SENSORS_GET_DESCRIPTIONS_IN_LEN(EFX_DYNAMIC_SENSOR_INFO_READ_MAX_HANDLES));
	struct efx_dynamic_sensor_description *sensor = NULL;
	static int type_idx[EFX_HWMON_TYPES_COUNT] = {0};
	unsigned int handle;
	int i, rc = 0;
	size_t outlen;

	for (i = 0; i < num_handles; i++) {
		MCDI_SET_ARRAY_DWORD(inbuf,
			       DYNAMIC_SENSORS_GET_DESCRIPTIONS_IN_HANDLES, i,
			       handle_list[i]);
	}
	rc = efx_mcdi_rpc(efx, MC_CMD_DYNAMIC_SENSORS_GET_DESCRIPTIONS, inbuf,
			  MC_CMD_DYNAMIC_SENSORS_GET_DESCRIPTIONS_IN_LEN(i),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	i = 0;
	/*
	 * outlen determins the number of handles returned if any handles
	 * are dropped by FW
	 */
	if (outlen % MC_CMD_DYNAMIC_SENSORS_GET_DESCRIPTIONS_OUT_SENSORS_LEN){
		WARN_ON(1);
		return -EINVAL;
	}
	while (outlen) {
		efx_dword_t *str_ptr = MCDI_ARRAY_STRUCT_PTR(outbuf,
							     DYNAMIC_SENSORS_GET_DESCRIPTIONS_OUT_SENSORS,
							     i);

		handle = MCDI_DWORD(str_ptr, DYNAMIC_SENSORS_DESCRIPTION_HANDLE);
		sensor = efx_mcdi_get_dynamic_sensor(efx, handle);
		/* check if sensor was dropped */
		if (IS_ERR(sensor)) {
			i++;
			outlen -= MC_CMD_DYNAMIC_SENSORS_GET_DESCRIPTIONS_OUT_SENSORS_LEN;
			continue;
		}
		memcpy(sensor->name,
		       MCDI_PTR(str_ptr, DYNAMIC_SENSORS_DESCRIPTION_NAME),
		       MC_CMD_DYNAMIC_SENSORS_DESCRIPTION_NAME_LEN);
		sensor->type = MCDI_DWORD(str_ptr, DYNAMIC_SENSORS_DESCRIPTION_TYPE);

		sensor->limits[EFX_SENSOR_LIMIT_WARNING_LO] =
			MCDI_DWORD(str_ptr, DYN_SENSOR_LIMIT_LO_WARNING);
		efx_mcdi_mon_add_attr(efx, sensor->idx,
				      sensor->type,
				      sensor->limits[EFX_SENSOR_LIMIT_WARNING_LO],
				      type_idx[sensor->type],
				      EFX_HWMON_MIN, true);

		sensor->limits[EFX_SENSOR_LIMIT_WARNING_HI] =
			MCDI_DWORD(str_ptr, DYN_SENSOR_LIMIT_HI_WARNING);
		efx_mcdi_mon_add_attr(efx, sensor->idx,
				      sensor->type,
				      sensor->limits[EFX_SENSOR_LIMIT_WARNING_HI],
				      type_idx[sensor->type],
				      EFX_HWMON_MAX, true);

		netif_dbg(efx, drv, efx->net_dev,
			  "Adding sensor %s, type %d, limits(%u, %u)\n",
			  sensor->name, sensor->type,
			  sensor->limits[EFX_SENSOR_LIMIT_WARNING_LO],
			  sensor->limits[EFX_SENSOR_LIMIT_WARNING_HI]);

		efx_mcdi_mon_add_attr(efx, sensor->idx, sensor->type, 0,
				      type_idx[sensor->type], EFX_HWMON_LABEL,
				      true);
		efx_mcdi_mon_add_attr(efx, sensor->idx, sensor->type, 0,
				      type_idx[sensor->type], EFX_HWMON_INPUT,
				      true);
		type_idx[sensor->type]++;
		i++;
		outlen -= MC_CMD_DYNAMIC_SENSORS_GET_DESCRIPTIONS_OUT_SENSORS_LEN;
	}

	return 0;
}

/*
 * This function is assumed to be called only after @has_dynamic_sensors
 * has returned true or DYNAMIC_SENSOR_LIST event received
 */
static int efx_mcdi_read_dynamic_sensor_info(struct efx_nic *efx)
{
	/*
	 * limiting maximum sensors per read to 4 to avoid
	 * -Werror=frame-larger-than=]
	 */
	unsigned int handles[EFX_DYNAMIC_SENSOR_INFO_READ_MAX_HANDLES];
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	struct efx_dynamic_sensor_description *sensor;
	unsigned int j, i = 0;
	int rc = 0;

	sensor = (struct efx_dynamic_sensor_description *)hwmon->sensor_list;
	mutex_lock(&hwmon->update_lock);
	for (j = 0; j < hwmon->n_dynamic_sensors; j++) {
		handles[i] = sensor[j].handle;
		i++;
		if ((i == EFX_DYNAMIC_SENSOR_INFO_READ_MAX_HANDLES) ||
		    (j == (hwmon->n_dynamic_sensors - 1))) {
			rc = efx_mcdi_read_dynamic_sensor_list_info(efx,
								    handles, i);
			if (!rc)
				i = 0;
			else
				break;
		}
	}
	mutex_unlock(&hwmon->update_lock);

	return rc;
}

static int efx_mcdi_read_sensor_info(struct efx_nic *efx, unsigned int n_pages)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_SENSOR_INFO_OUT_LENMAX);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SENSOR_INFO_EXT_IN_LEN);
	u8 n_temp, n_cool, n_in, n_curr, n_power;
	u32 type, mask = 0, page = 0;
	size_t outlen;
	int i, j, rc;

	n_temp = n_curr = n_cool = n_in = n_power = 0;
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
					return 0;

				MCDI_SET_DWORD(inbuf, SENSOR_INFO_EXT_IN_PAGE,
					       page);
				rc = efx_mcdi_rpc(efx, MC_CMD_SENSOR_INFO,
						  inbuf, sizeof(inbuf),
						  outbuf, sizeof(outbuf),
						  &outlen);
				if (rc)
					return rc;
				if (outlen < MC_CMD_SENSOR_INFO_OUT_LENMIN)
					return -EIO;

				mask = (MCDI_DWORD(outbuf,
						   SENSOR_INFO_OUT_MASK) &
					~(1 << MC_CMD_SENSOR_PAGE0_NEXT));

				/* Check again for short response */
				if (outlen <
				    MC_CMD_SENSOR_INFO_OUT_LEN(hweight32(mask)))
					return -EIO;
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
				      EFX_HWMON_INPUT, false);
		if (min1 != max1) {

			if (hwmon_type != hwmon_power) {
				efx_mcdi_mon_add_attr(efx, i, type, min1,
						      file_index,
						      EFX_HWMON_MIN, false);
			}

			efx_mcdi_mon_add_attr(efx, i, type, max1, file_index,
					      EFX_HWMON_MAX, false);

		}
		if (min2 != max2) {
			/* Assume max2 is critical value.
			 * But we have no good way to expose min2.
			 */
			efx_mcdi_mon_add_attr(efx, i, type, max2,
					      file_index,
					      EFX_HWMON_CRIT, false);
		}

		efx_mcdi_mon_add_attr(efx, i, type, 0, file_index,
				      EFX_HWMON_ALARM, false);

		if (type < ARRAY_SIZE(efx_mcdi_sensor_type) &&
		    efx_mcdi_sensor_type[type].label) {
			efx_mcdi_mon_add_attr(efx, i, type, 0, file_index,
					      EFX_HWMON_LABEL, false);
		}
	}

	return 0;
}

static int efx_mcdi_get_num_sensors(struct efx_nic *efx,
				     unsigned int *n_sensors,
				     unsigned int *n_pages)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_SENSOR_INFO_OUT_LENMAX);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SENSOR_INFO_EXT_IN_LEN);
	unsigned int page = 0;
	size_t outlen;
	u32 mask = 0;
	int rc;

	do {
		MCDI_SET_DWORD(inbuf, SENSOR_INFO_EXT_IN_PAGE, page);

		rc = efx_mcdi_rpc(efx, MC_CMD_SENSOR_INFO, inbuf, sizeof(inbuf),
				  outbuf, sizeof(outbuf), &outlen);
		if (rc)
			return rc;
		if (outlen < MC_CMD_SENSOR_INFO_OUT_LENMIN)
			return -EIO;

		mask = MCDI_DWORD(outbuf, SENSOR_INFO_OUT_MASK);
		*n_sensors += hweight32(mask &
					~(1 << MC_CMD_SENSOR_PAGE0_NEXT));
		++page;
	} while (mask & (1 << MC_CMD_SENSOR_PAGE0_NEXT));
	*n_pages = page;

	return 0;
}

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

static int efx_mcdi_mon_get_dynamic_entry(struct device *dev,
					  unsigned int index,
					  efx_dword_t **entry)
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
		rc = efx_mcdi_dynamic_sensor_reading_update(efx);

	/*
	 * Copy out the requested entry. Entries for dynamic sensors are
	 * commposed by three efx_dword_t values: handle, value, state.
	 */
	*entry = &((efx_dword_t *)hwmon->dma_buf.addr)[index * 3];

	mutex_unlock(&hwmon->update_lock);

	return rc;
}

static int efx_mcdi_mon_get_value(struct device *dev, unsigned int index,
				  enum hwmon_sensor_types hwmon_type,
				  unsigned int *value)
{
	struct efx_nic *efx = dev_get_drvdata(dev);
	efx_dword_t *dyn_entry;
	unsigned int state;
	efx_dword_t entry;
	int rc;

	if (efx_nic_has_dynamic_sensors(efx)) {
		rc = efx_mcdi_mon_get_dynamic_entry(dev, index, &dyn_entry);
		if (rc)
			return rc;

		state = MCDI_DWORD(dyn_entry, DYNAMIC_SENSORS_READING_STATE);
		if (state == MC_CMD_SENSOR_STATE_NO_READING)
			return -EBUSY;

		*value = MCDI_DWORD(dyn_entry, DYNAMIC_SENSORS_READING_VALUE);
	} else {
		rc = efx_mcdi_mon_get_entry(dev, index, &entry);
		if (rc)
			return rc;
		state = EFX_DWORD_FIELD(entry,
					MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_STATE);
		if (state == MC_CMD_SENSOR_STATE_NO_READING)
			return -EBUSY;
		*value = EFX_DWORD_FIELD(entry,
					 MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_VALUE);
	}

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
	struct efx_nic *efx = dev_get_drvdata(dev);
	efx_dword_t entry, *dyn_entry;
	int rc;

	if (efx_nic_has_dynamic_sensors(efx)) {
		rc = efx_mcdi_mon_get_dynamic_entry(dev, index, &dyn_entry);
		if (rc)
			return rc;
		rc = MCDI_DWORD(dyn_entry, DYNAMIC_SENSORS_READING_STATE);
	} else {
		rc = efx_mcdi_mon_get_entry(dev, index, &entry);
		if (rc)
			return rc;
		rc = EFX_DWORD_FIELD(entry,
				     MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_STATE);
	}
	return rc;
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_HWMON_DEVICE_REGISTER_WITH_INFO)
static ssize_t efx_mcdi_mon_show_name(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", KBUILD_MODNAME);
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
	return scnprintf(buf, PAGE_SIZE, "%u\n", value);
}

static ssize_t efx_mcdi_mon_show_limit(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	unsigned int value = efx_mcdi_mon_get_limit(mon_attr);

	return scnprintf(buf, PAGE_SIZE, "%u\n", value);
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

	return scnprintf(buf, PAGE_SIZE, "%d\n", state != MC_CMD_SENSOR_STATE_OK);
}

static ssize_t efx_mcdi_mon_show_label(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	return scnprintf(buf, PAGE_SIZE, "%s\n",
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
	struct efx_nic *efx_temp = dev_get_drvdata(dev);
	struct efx_dynamic_sensor_description *sensor;
	struct efx_mcdi_mon_attribute *mon_attr =
		efx_hwmon_get_attribute(efx, type, attr, channel);

	if (!mon_attr)
		return 1;

	if (mon_attr->is_dynamic) {
		sensor = efx_mcdi_get_dynamic_sensor(efx_temp, mon_attr->index + 1);
		if (!sensor) {
			WARN(1, "%s: sensor not found\n", __func__);
			*str = NULL;
		} else {
			*str = sensor->name;
		}
	} else {
		*str = (char *) efx_mcdi_sensor_type[mon_attr->type].label;
	}
	return 0;
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
	EFX_HWMON_IN_CONFIG,
	EFX_HWMON_IN_CONFIG,
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
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
	EFX_HWMON_CURR_CONFIG,
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
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
	EFX_HWMON_POWER_CONFIG,
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

static int efx_mcdi_hwmon_probe(struct efx_nic *efx, unsigned int n_sensors,
				unsigned int n_pages, bool has_dynamic_sensors)
{
	unsigned int sensor_entry_len = MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_LEN;
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	unsigned int n_attrs;
	int rc;

	if (has_dynamic_sensors)
		sensor_entry_len = MC_CMD_DYNAMIC_SENSORS_GET_READINGS_OUT_VALUES_LEN;

	rc = efx_nic_alloc_buffer(efx, &hwmon->dma_buf,
				  n_sensors * sensor_entry_len, GFP_KERNEL);
	if (rc)
		return rc;


	/* Allocate space for the maximum possible number of
	 * attributes for this set of sensors: name of the driver plus
	 * value, min, max, crit, alarm and label for each sensor.
	 */
	n_attrs = 1 + 6 * n_sensors;
	hwmon->attrs = kcalloc(n_attrs, sizeof(*hwmon->attrs), GFP_KERNEL);
	if (!hwmon->attrs)
		return -ENOMEM;

	efx_mcdi_mon_add_attr(efx, 0, 0, 0, 0, EFX_HWMON_NAME, false);

	if (has_dynamic_sensors)
		rc = efx_mcdi_read_dynamic_sensor_info(efx);
	else
		rc = efx_mcdi_read_sensor_info(efx, n_pages);

	if (rc)
		return rc;

	hwmon->device = hwmon_device_register_with_info(&efx->pci_dev->dev,
							efx->name, efx,
							efx_hwmon_chip_info_p,
							NULL);
	if (IS_ERR(hwmon->device))
		return PTR_ERR(hwmon->device);
	rc = efx_mcdi_mon_create_files(&efx->pci_dev->dev, hwmon);

	return rc;
}

int efx_mcdi_mon_probe(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	unsigned int n_pages, n_sensors, page;
	bool has_dynamic_sensors = efx_nic_has_dynamic_sensors(efx);
	int rc;

	/* Do not probe twice */
	if (hwmon->dma_buf.addr)
		return 0;

	if (!has_dynamic_sensors && efx->type->has_dynamic_sensors) {
		netif_err(efx, hw, efx->net_dev,
			  "Expected dynamic sensor feature not supported by FW\n");
		return 0;
	}

	/* Find out how many sensors are present */
	n_sensors = 0;
	page = 0;

	mutex_init(&hwmon->update_lock);

	if (has_dynamic_sensors) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
		rhashtable_init(&hwmon->sensor_table, &sensor_entry_params);
		rc = efx_mcdi_read_dynamic_sensor_list(efx);
		n_sensors = hwmon->n_dynamic_sensors;
#else
		netif_err(efx, hw, efx->net_dev,
			  "Kernel is too old to support dynamic sensors\n");
		rc = -ENOTSUPP;
#endif
	} else {
		rc = efx_mcdi_get_num_sensors(efx, &n_sensors, &n_pages);
	}

	if (rc)
		return rc;

	if (!n_sensors)
		return 0;

	rc  = efx_mcdi_hwmon_probe(efx, n_sensors, n_pages,
				   has_dynamic_sensors);
	if (rc) {
		efx_mcdi_mon_remove(efx);
	} else {
		mutex_lock(&hwmon->update_lock);
		if (has_dynamic_sensors)
			efx_mcdi_dynamic_sensor_reading_update(efx);
		else
			efx_mcdi_mon_update(efx);
		mutex_unlock(&hwmon->update_lock);
	}

	return rc;
}

static void efx_mcdi_hwmon_remove(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);

	mutex_lock(&hwmon->update_lock);

	efx_mcdi_mon_remove_files(&efx->pci_dev->dev, hwmon);
	if (!IS_ERR_OR_NULL(hwmon->device))
		hwmon_device_unregister(hwmon->device);
	if (hwmon->attrs)
		kfree(hwmon->attrs);
	hwmon->attrs = NULL;
	hwmon->n_attrs = 0;
	if (hwmon->sensor_list)
		kfree(hwmon->sensor_list);
	hwmon->sensor_list = NULL;
	hwmon->n_dynamic_sensors = 0;

	efx_nic_free_buffer(efx, &hwmon->dma_buf);
	mutex_unlock(&hwmon->update_lock);
}

void efx_mcdi_mon_remove(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);

	if (!hwmon || !hwmon->dma_buf.addr)
		return;
	efx_mcdi_hwmon_remove(efx);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
	if (efx_nic_has_dynamic_sensors(efx))
		rhashtable_free_and_destroy(&hwmon->sensor_table,
					    NULL,
					    NULL);
#endif
}

#endif /* CONFIG_SFC_MCDI_MON */
