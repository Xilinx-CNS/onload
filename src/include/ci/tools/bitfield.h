/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2020 Xilinx, Inc. */
/****************************************************************************
 * Copyright 2009-2009: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef __CI_TOOLS_BITFIELD_H__
#define __CI_TOOLS_BITFIELD_H__

typedef union ci_dword_u {
  ci_uint32 u32[1];
} ci_dword_t;

typedef union ci_qword_u {
  ci_dword_t dword[2];
  ci_uint32 u32[2];
  ci_uint64 u64[1];
} ci_qword_t;

typedef union ci_oword_u {
  ci_dword_t dword[4];
  ci_qword_t qword[2];
  ci_uint32 u32[4];
  ci_uint64 u64[2];
} ci_oword_t;

#define CI_DUMMY_FIELD_LBN 0
#define CI_DUMMY_FIELD_WIDTH 0

#define CI_BYTE_0_LBN 0
#define CI_BYTE_0_WIDTH 8
#define CI_BYTE_1_LBN 8
#define CI_BYTE_1_WIDTH 8
#define CI_BYTE_2_LBN 16
#define CI_BYTE_2_WIDTH 8
#define CI_BYTE_3_LBN 24
#define CI_BYTE_3_WIDTH 8

#define CI_DWORD_0_LBN 0
#define CI_DWORD_0_WIDTH 32
#define CI_DWORD_1_LBN 32
#define CI_DWORD_1_WIDTH 32
#define CI_DWORD_2_LBN 64
#define CI_DWORD_2_WIDTH 32
#define CI_DWORD_3_LBN 96
#define CI_DWORD_3_WIDTH 32
#define CI_QWORD_0_LBN 0
#define CI_QWORD_0_WIDTH 64
#define CI_QWORD_1_LBN 64
#define CI_QWORD_1_WIDTH 64

/* Field accessors */
#define CI_BITFIELD_VAL(_field, _attribute)	\
  _field ## _ ## _attribute
#define CI_BITFIELD_LOW_BIT(_field)		\
  CI_BITFIELD_VAL(_field, LBN)
#define CI_BITFIELD_WIDTH(_field)		\
  CI_BITFIELD_VAL(_field, WIDTH)
#define CI_BITFIELD_HIGH_BIT(_field)				\
  (CI_BITFIELD_LOW_BIT(_field) + CI_BITFIELD_WIDTH(_field) - 1)

/* Mask generators */
#define CI_BITFIELD_MASK64(_width)					\
  ((_width) == 64 ? ~((ci_uint64) 0) :					\
   ((((ci_uint64) 1) << (_width)) - 1))
#define CI_BITFIELD_MASK32(_width)					\
  ((_width) == 32 ? ~((ci_uint32) 0) :					\
   ((((ci_uint32) 1) << (_width)) - 1))

/* String formatters */
#define CI_DWORD_FMT "%08x"
#define CI_QWORD_FMT "%08x:%08x"
#define CI_OWORD_FMT "%08x:%08x:%08x:%08x"
#define CI_DWORD_VAL(_dword)				\
  ((unsigned int) CI_BSWAP_LE32((_dword).u32[0]))
#define CI_QWORD_VAL(_qword)				\
  ((unsigned int) CI_BSWAP_LE32((_qword).u32[0])),	\
  ((unsigned int) CI_BSWAP_LE32((_qword).u32[1]))
#define CI_OWORD_VAL(_oword)				\
  ((unsigned int) CI_BSWAP_LE32((_oword).u32[0])),	\
  ((unsigned int) CI_BSWAP_LE32((_oword).u32[1])),	\
  ((unsigned int) CI_BSWAP_LE32((_oword).u32[2])),	\
  ((unsigned int) CI_BSWAP_LE32((_oword).u32[3]))

/* Initializers */
#define CI_DWORD_INIT(_val)			\
  { { (_val) } }

/* Extract bit field portion [low, high) from native-endian element
 * containing bits [min, max) */
#define CI_BITFIELD_EXTRACT_NATIVE(_element, _min, _max, _low, _high)	\
  (((_low > _max) || (_high < _min)) ? 0 :				\
   ((_low > _min) ?							\
    ((_element) >> (_low - _min)) :					\
    ((_element) << (_min - _low))))

#define CI_BITFIELD_EXTRACT64(_element, _min, _max, _low, _high)  \
  CI_BITFIELD_EXTRACT_NATIVE(CI_BSWAP_LE64(_element), _min, _max, \
			     _low, _high)

#define CI_BITFIELD_EXTRACT32(_element, _min, _max, _low, _high)	\
  CI_BITFIELD_EXTRACT_NATIVE(CI_BSWAP_LE32(_element), _min, _max,	\
			     _low, _high)

/* 64bit region extraction */
#define CI_EXTRACT_OWORD64(_oword, _low, _high)		\
  ((CI_BITFIELD_EXTRACT64((_oword).u64[0], 0, 63, _low, _high) |	\
    CI_BITFIELD_EXTRACT64((_oword).u64[1], 64, 127, _low, _high)) &	\
   CI_BITFIELD_MASK64(_high + 1 - _low))

#define CI_EXTRACT_QWORD64(_qword, _low, _high)		\
  (CI_BITFIELD_EXTRACT64((_qword).u64[0], 0, 63, _low, _high) &	\
   CI_BITFIELD_MASK64(_high + 1 - _low))

/* 32bit region extraction */
#define CI_EXTRACT_OWORD32(_oword, _low, _high)				\
  ((CI_BITFIELD_EXTRACT64((_oword).u32[0], 0, 31, _low, _high) |	\
    CI_BITFIELD_EXTRACT64((_oword).u32[1], 32, 63, _low, _high) |	\
    CI_BITFIELD_EXTRACT64((_oword).u32[2], 64, 95, _low, _high) |	\
    CI_BITFIELD_EXTRACT64((_oword).u32[3], 96, 127, _low, _high)) &	\
   CI_BITFIELD_MASK32(_high + 1 - _low))

#define CI_EXTRACT_QWORD32(_qword, _low, _high)				\
  ((CI_BITFIELD_EXTRACT64((_qword).u32[0], 0, 31, _low, _high) |	\
    CI_BITFIELD_EXTRACT64((_qword).u32[1], 32, 63, _low, _high)) &	\
   CI_BITFIELD_MASK32(_high + 1 - _low))

#define CI_EXTRACT_DWORD(_dword, _low, _high)		\
  (CI_BITFIELD_EXTRACT32((_dword).u32[0], 0, 31, _low, _high) &	\
   CI_BITFIELD_MASK32(_high + 1 - _low))

/* 64bit field extraction */
#define CI_OWORD_FIELD64(_oword, _field)			\
  CI_EXTRACT_OWORD64(_oword, CI_BITFIELD_LOW_BIT(_field),	\
		     CI_BITFIELD_HIGH_BIT(_field))

#define CI_QWORD_FIELD64(_qword, _field)			\
  CI_EXTRACT_QWORD64(_qword, CI_BITFIELD_LOW_BIT(_field),	\
		     CI_BITFIELD_HIGH_BIT(_field))

/* 32bit field extraction */
#define CI_OWORD_FIELD32(_oword, _field)			\
  CI_EXTRACT_OWORD32(_oword, CI_BITFIELD_LOW_BIT(_field),	\
		     CI_BITFIELD_HIGH_BIT(_field))

#define CI_QWORD_FIELD32(_qword, _field)			\
  CI_EXTRACT_QWORD32(_qword, CI_BITFIELD_LOW_BIT(_field),	\
		     CI_BITFIELD_HIGH_BIT(_field))

#define CI_DWORD_FIELD(_dword, _field)			\
  CI_EXTRACT_DWORD(_dword, CI_BITFIELD_LOW_BIT(_field),	\
		   CI_BITFIELD_HIGH_BIT(_field))

/* 64bit bitfield comparion */
#define CI_OWORD_IS_ZERO64(_oword)		\
  (((_oword).u64[0] | (_oword).u64[1]) == 0)

#define CI_QWORD_IS_ZERO64(_qword)		\
  ((_qword).u64[0] == 0)

#define CI_OWORD_IS_ALL_ONES64(_oword)				\
  (((_oword).u64[0] & (_oword).u64[1]) == ~((uint64) 0))

#define CI_QWORD_IS_ALL_ONES64(_qword)		\
  ((_qword).u64[0] == ~((uint64) 0))

/* 32bit bitfield comparison */
#define CI_OWORD_IS_ZERO32(_oword)					\
  (((_oword).u32[0] | (_oword).u32[1] |					\
    (_oword).u32[2] | (_oword).u32[3]) == 0)

#define CI_QWORD_IS_ZERO32(_qword)		\
  (((_qword).u32[0] | (_qword).u32[1]) == 0)

#define CI_OWORD_IS_ALL_ONES32(_oword)				\
  (((_oword).u32[0] & (_oword).u32[1] &				\
    (_oword).u32[2] & (_oword).u32[3]) == ~((uint32) 0))

#define CI_QWORD_IS_ALL_ONES32(_qword)		\
  (((_qword).u32[0] | (_qword).u32[1]) == ~((uint64) 0))

#if CI_WORD_SIZE == 8
#define CI_OWORD_FIELD CI_OWORD_FIELD64
#define CI_QWORD_FIELD CI_QWORD_FIELD64
#define CI_OWORD_IS_ZERO CI_OWORD_IS_ZERO64
#define CI_QWORD_IS_ZERO CI_QWORD_IS_ZERO64
#define CI_OWORD_IS_ALL_ONES CI_OWORD_IS_ALL_ONES64
#define CI_QWORD_IS_ALL_ONES CI_QWORD_IS_ALL_ONES64
#else
#define CI_OWORD_FIELD CI_OWORD_FIELD32
#define CI_QWORD_FIELD CI_QWORD_FIELD32
#define CI_OWORD_IS_ZERO CI_OWORD_IS_ZERO32
#define CI_QWORD_IS_ZERO CI_QWORD_IS_ZERO32
#define CI_OWORD_IS_ALL_ONES CI_OWORD_IS_ALL_ONES32
#define CI_QWORD_IS_ALL_ONES CI_QWORD_IS_ALL_ONES32
#endif

/* Construct bitfield patterns: Creates the portion of the bit field
 * [_low, _high) that lies within the range [_min, _max) */
#define CI_BITFIELD_INSERT_NATIVE64(_min, _max, _low, _high, _value)	\
  (((_low > _max) || (_low < _min)) ? 0 :				\
   ((_low > _min) ?							\
    (((ci_uint64) (_value)) << (_low - _min)) :				\
    (((ci_uint64) (_value)) >> (_min - _low))))

#define CI_BITFIELD_INSERT_NATIVE32(_min, _max, _low, _high, _value)	\
  (((_low > _max) || (_low < _min)) ? 0 :				\
   ((_low > _min) ?							\
    (((ci_uint32) (_value)) << (_low - _min)) :				\
    (((ci_uint32) (_value)) >> (_min - _low))))

#if CI_WORD_SIZE == 8
#define CI_BITFIELD_INSERT_NATIVE CI_BITFIELD_INSERT_NATIVE64
#else
#define CI_BITFIELD_INSERT_NATIVE CI_BITFIELD_INSERT_NATIVE32
#endif

#define CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field, _value)	\
  CI_BITFIELD_INSERT_NATIVE(_min, _max, CI_BITFIELD_LOW_BIT(_field),	\
			    CI_BITFIELD_HIGH_BIT(_field), _value)

/* Construct a bitfield from multiple field,value tuples */
#define CI_BITFIELD_INSERT_FIELDS_NATIVE(_min, _max,			\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11)						\
  (CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field1, _value1) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field2, _value2) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field3, _value3) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field4, _value4) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field5, _value5) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field6, _value6) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field7, _value7) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field8, _value8) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field9, _value9) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field10, _value10) |	\
   CI_BITFIELD_INSERT_FIELD_NATIVE(_min, _max, _field11, _value11))

/* 64bit field cnostruction */
#define CI_BITFIELD_INSERT_FIELDS64(_min, _max,				\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11)						\
  CI_BSWAP_LE64(CI_BITFIELD_INSERT_FIELDS_NATIVE(_min, _max,		\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11))

#define CI_POPULATE_OWORD64(_oword,					\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11)						\
  do {									\
    (_oword).u64[0] = CI_BITFIELD_INSERT_FIELDS64(0, 63,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
    (_oword).u64[1] = CI_BITFIELD_INSERT_FIELDS64(64, 127,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
  } while (0)

#define CI_POPULATE_QWORD64(_qword,					\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11)						\
  do {									\
    (_qword).u64[0] = CI_BITFIELD_INSERT_FIELDS64(0, 63,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
  } while (0)

/* 32bit field construction */
#define CI_BITFIELD_INSERT_FIELDS32(_min, _max,				\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11)						\
  CI_BSWAP_LE32(CI_BITFIELD_INSERT_FIELDS_NATIVE(_min, _max,		\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11))

#define CI_POPULATE_OWORD32(_oword,					\
	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11)						\
  do {									\
    (_oword).u32[0] = CI_BITFIELD_INSERT_FIELDS32(0, 31,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
    (_oword).u32[1] = CI_BITFIELD_INSERT_FIELDS32(32, 63,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
    (_oword).u32[2] = CI_BITFIELD_INSERT_FIELDS32(64, 95,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
    (_oword).u32[3] = CI_BITFIELD_INSERT_FIELDS32(96, 127,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
  } while (0)

#define CI_POPULATE_QWORD32(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11)						\
  do {									\
    (_qword).u32[0] = CI_BITFIELD_INSERT_FIELDS64(0, 31,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
    (_qword).u32[1] = CI_BITFIELD_INSERT_FIELDS64(32, 63,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);						\
  } while (0)

#define CI_POPULATE_DWORD(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
    	_field7, _value7, _field8, _value8, _field9, _value9,		\
        _field10, _value10, _field11, _value11)				\
  do {									\
    (_dword).u32[0] = CI_BITFIELD_INSERT_FIELDS32(0, 31,		\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10, _field11, _value11);			\
  } while (0)

#if CI_WORD_SIZE == 8
#define CI_POPULATE_OWORD CI_POPULATE_OWORD64
#define CI_POPULATE_QWORD CI_POPULATE_QWORD64
#else
#define CI_POPULATE_OWORD CI_POPULATE_OWORD32
#define CI_POPULATE_QWORD CI_POPULATE_QWORD32
#endif

/* Populate oword fields*/
#define CI_POPULATE_OWORD_11 CI_POPULATE_OWORD

#define CI_POPULATE_OWORD_10(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
        _field7, _value7, _field8, _value8, _field9, _value9,		\
        _field10, _value10)                                             \
    CI_POPULATE_OWORD_11(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
        _field7, _value7, _field8, _value8, _field9, _value9,		\
        _field10, _value10)

#define CI_POPULATE_OWORD_9(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9)		\
    CI_POPULATE_OWORD_10(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9)

#define CI_POPULATE_OWORD_8(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8)				\
    CI_POPULATE_OWORD_9(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8)

#define CI_POPULATE_OWORD_7(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7)						\
    CI_POPULATE_OWORD_8(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7)

#define CI_POPULATE_OWORD_6(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6)		\
    CI_POPULATE_OWORD_7(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6)

#define CI_POPULATE_OWORD_5(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5)				\
    CI_POPULATE_OWORD_6(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5)

#define CI_POPULATE_OWORD_4(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4)						\
    CI_POPULATE_OWORD_5(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4)

#define CI_POPULATE_OWORD_3(_oword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3)		\
    CI_POPULATE_OWORD_4(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3)

#define CI_POPULATE_OWORD_2(_oword, _field1, _value1, _field2, _value2)	\
    CI_POPULATE_OWORD_3(_oword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2)

#define CI_POPULATE_OWORD_1(_oword, _field1, _value1)			\
    CI_POPULATE_OWORD_2(_oword, CI_DUMMY_FIELD, 0, _field1, _value1)

/* Populate qword fields*/
#define CI_POPULATE_QWORD_11 CI_POPULATE_QWORD

#define CI_POPULATE_QWORD_10(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
        _field7, _value7, _field8, _value8, _field9, _value9,		\
        _field10, _value10)                                             \
    CI_POPULATE_QWORD_11(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
        _field7, _value7, _field8, _value8, _field9, _value9,		\
        _field10, _value10)

#define CI_POPULATE_QWORD_9(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9)		\
    CI_POPULATE_QWORD_10(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9)

#define CI_POPULATE_QWORD_8(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8)				\
    CI_POPULATE_QWORD_9(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8)

#define CI_POPULATE_QWORD_7(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7)						\
    CI_POPULATE_QWORD_8(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7)

#define CI_POPULATE_QWORD_6(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6)		\
    CI_POPULATE_QWORD_7(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6)

#define CI_POPULATE_QWORD_5(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5)				\
    CI_POPULATE_QWORD_6(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5)

#define CI_POPULATE_QWORD_4(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4)						\
    CI_POPULATE_QWORD_5(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4)

#define CI_POPULATE_QWORD_3(_qword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3)		\
    CI_POPULATE_QWORD_4(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3)

#define CI_POPULATE_QWORD_2(_qword, _field1, _value1, _field2, _value2)	\
    CI_POPULATE_QWORD_3(_qword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2)

#define CI_POPULATE_QWORD_1(_qword, _field1, _value1)			\
    CI_POPULATE_QWORD_2(_qword, CI_DUMMY_FIELD, 0, _field1, _value1)

/* Populate dword fields */
#define CI_POPULATE_DWORD_11 CI_POPULATE_DWORD

#define CI_POPULATE_DWORD_10(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
        _field7, _value7, _field8, _value8, _field9, _value9,		\
        _field10, _value10)                                             \
    CI_POPULATE_DWORD_11(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
        _field7, _value7, _field8, _value8, _field9, _value9,		\
	_field10, _value10)

#define CI_POPULATE_DWORD_9(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9)		\
    CI_POPULATE_DWORD_10(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8, _field9, _value9)

#define CI_POPULATE_DWORD_8(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8)				\
    CI_POPULATE_DWORD_9(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7, _field8, _value8)

#define CI_POPULATE_DWORD_7(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7)						\
    CI_POPULATE_DWORD_8(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6,		\
	_field7, _value7)

#define CI_POPULATE_DWORD_6(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6)		\
    CI_POPULATE_DWORD_7(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5, _field6, _value6)

#define CI_POPULATE_DWORD_5(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5)				\
    CI_POPULATE_DWORD_6(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4, _field5, _value5)

#define CI_POPULATE_DWORD_4(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4)						\
    CI_POPULATE_DWORD_5(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3,		\
	_field4, _value4)

#define CI_POPULATE_DWORD_3(_dword,					\
   	_field1, _value1, _field2, _value2, _field3, _value3)		\
    CI_POPULATE_DWORD_4(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2, _field3, _value3)

#define CI_POPULATE_DWORD_2(_dword, _field1, _value1, _field2, _value2)	\
    CI_POPULATE_DWORD_3(_dword, CI_DUMMY_FIELD, 0,			\
   	_field1, _value1, _field2, _value2)

#define CI_POPULATE_DWORD_1(_dword, _field1, _value1)			\
    CI_POPULATE_DWORD_2(_dword, CI_DUMMY_FIELD, 0, _field1, _value1)

/* Zero fields */
#define CI_ZERO_OWORD(_oword)				\
    CI_POPULATE_OWORD_1(_oword, CI_DUMMY_FIELD, 0)

#define CI_ZERO_QWORD(_qword)				\
    CI_POPULATE_QWORD_1(_qword, CI_DUMMY_FIELD, 0)

#define CI_ZERO_DWORD(_dword)				\
    CI_POPULATE_DWORD_1(_dword, CI_DUMMY_FIELD, 0)

/* Set fields */
#define CI_SET_OWORD(_oword)				\
  do {							\
    (_oword).u32[0] = ~((ci_uint32) 0);			\
    (_oword).u32[1] = ~((ci_uint32) 0);			\
    (_oword).u32[2] = ~((ci_uint32) 0);			\
    (_oword).u32[3] = ~((ci_uint32) 0);			\
  } while (0)

#define CI_SET_QWORD(_qword)				\
  do {							\
    (_qword).u32[0] = ~((ci_uint32) 0);			\
    (_qword).u32[1] = ~((ci_uint32) 0);			\
  } while (0)

#define CI_SET_DWORD(_dword)				\
  do {							\
    (_dword).u32[0] = ~((ci_uint32) 0);			\
  } while (0)

#define CI_BITFIELD_INSERT64(_min, _max, _low, _high, _value)		\
    CI_BSWAP_LE64(CI_BITFIELD_INSERT_NATIVE(_min, _max,			\
					    _low, _high, _value))

#define CI_BITFIELD_INSERT32(_min, _max, _low, _high, _value)		\
    CI_BSWAP_LE32(CI_BITFIELD_INSERT_NATIVE(_min, _max,			\
					    _low, _high, _value))

#define CI_BITFIELD_INPLACE_MASK64(_min, _max, _low, _high)	\
    CI_BITFIELD_INSERT64(_min, _max, _low, _high,		\
			 CI_BITFIELD_MASK64(_high + 1 - _low))
    
#define CI_BITFIELD_INPLACE_MASK32(_min, _max, _low, _high)	\
    CI_BITFIELD_INSERT32(_min, _max, _low, _high,		\
			 CI_BITFIELD_MASK32(_high + 1 - _low))

/* Set bit range in a pre-populated structure */
#define CI_SET_OWORD64(_oword, _low, _high, _value)			\
    do {								\
      (_oword).u64[0] =							\
	(((_oword).u64[0]						\
	  & ~CI_BITFIELD_INPLACE_MASK64(0, 63, _low, _high))		\
	 | CI_BITFIELD_INSERT64(0, 63, _low, _high, _value));		\
      (_oword).u64[1] =							\
	(((_oword).u64[1]						\
	  & ~CI_BITFIELD_INPLACE_MASK64(64, 127, _low, _high))		\
	 | CI_BITFIELD_INSERT64(64, 127, _low, _high, _value));		\
    } while (0)

#define CI_SET_QWORD64(_qword, _low, _high, _value)			\
    do {								\
      (_qword).u64[0] =							\
	(((_qword).u64[0]						\
	  & ~CI_BITFIELD_INPLACE_MASK64(0, 63, _low, _high))		\
	 | CI_BITFIELD_INSERT64(0, 63, _low, _high, _value));		\
    } while (0)

#define CI_SET_OWORD32(_oword, _low, _high, _value)			\
    do {								\
      (_oword).u32[0] =							\
	(((_oword).u32[0]						\
	  & ~CI_BITFIELD_INPLACE_MASK32(0, 31, _low, _high))		\
	 | CI_BITFIELD_INSERT32(0, 31, _low, _high, _value));		\
      (_oword).u32[1] =							\
	(((_oword).u32[1]						\
	  & ~CI_BITFIELD_INPLACE_MASK32(32, 63, _low, _high))		\
	 | CI_BITFIELD_INSERT32(32, 63, _low, _high, _value));		\
      (_oword).u32[2] =							\
	(((_oword).u32[2]						\
	  & ~CI_BITFIELD_INPLACE_MASK32(64, 95, _low, _high))		\
	 | CI_BITFIELD_INSERT32(64, 95, _low, _high, _value));		\
      (_oword).u32[3] =							\
	(((_oword).u32[3]						\
	  & ~CI_BITFIELD_INPLACE_MASK32(96, 127, _low, _high))		\
	 | CI_BITFIELD_INSERT32(96, 127, _low, _high, _value));		\
    } while (0)

#define CI_SET_QWORD32(_qword, _low, _high, _value)			\
    do {								\
      (_qword).u32[0] =							\
	(((_qword).u32[0]						\
	  & ~CI_BITFIELD_INPLACE_MASK32(0, 31, _low, _high))		\
	 | CI_BITFIELD_INSERT32(0, 31, _low, _high, _value));		\
      (_qword).u32[1] =							\
	(((_qword).u32[1]						\
	  & ~CI_BITFIELD_INPLACE_MASK32(32, 63, _low, _high))		\
	 | CI_BITFIELD_INSERT32(32, 63, _low, _high, _value));		\
    } while (0)

#define CI_SET_DWORD32(_dword, _low, _high, _value)			\
    do {								\
      (_dword).u32[0] =							\
	(((_dword).u32[0]						\
	  & ~CI_BITFIELD_INPLACE_MASK32(0, 31, _low, _high))		\
	 | CI_BITFIELD_INSERT32(0, 31, _low, _high, _value));		\
    } while (0)

/* Set/Clear bits in a prepopulated structure. This is a performance
 * optimisation, to avoid a mask or set */

#define CI_SET_OWORD64_BIT(_oword, _bit)				\
  do {									\
    (_oword).u64[0] |= CI_BITFIELD_INPLACE_MASK64(0, 63, _bit, _bit);	\
    (_oword).u64[1] |= CI_BITFIELD_INPLACE_MASK64(64, 127, _bit, _bit);	\
  } while (0)

#define CI_CLEAR_OWORD64_BIT(_oword, _bit)				\
  do {									\
    (_oword).u64[0] &= ~CI_BITFIELD_INPLACE_MASK64(0, 63, _bit, _bit);	\
    (_oword).u64[1] &= ~CI_BITFIELD_INPLACE_MASK64(64, 127, _bit, _bit); \
  } while (0)

#define CI_SET_QWORD64_BIT(_qword, _bit)				\
  do {									\
    (_qword).u64[0] |= CI_BITFIELD_INPLACE_MASK64(0, 63, _bit, _bit);	\
  } while (0)

#define CI_CLEAR_QWORD64_BIT(_qword, _bit)				\
  do {									\
    (_qword).u64[0] &= ~CI_BITFIELD_INPLACE_MASK64(0, 63, _bit, _bit);	\
  } while (0)

#define CI_SET_OWORD32_BIT(_oword, _bit)				\
  do {									\
    (_oword).u32[0] |= CI_BITFIELD_INPLACE_MASK32(0, 31, _bit, _bit);	\
    (_oword).u32[1] |= CI_BITFIELD_INPLACE_MASK32(32, 63, _bit, _bit);	\
    (_oword).u32[2] |= CI_BITFIELD_INPLACE_MASK32(64, 95, _bit, _bit);	\
    (_oword).u32[3] |= CI_BITFIELD_INPLACE_MASK32(96, 127, _bit, _bit);	\
  } while (0)

#define CI_CLEAR_OWORD32_BIT(_oword, _bit)				\
  do {									\
    (_oword).u32[0] &= ~CI_BITFIELD_INPLACE_MASK32(0, 31, _bit, _bit);	\
    (_oword).u32[1] &= ~CI_BITFIELD_INPLACE_MASK32(32, 63, _bit, _bit);	\
    (_oword).u32[2] &= ~CI_BITFIELD_INPLACE_MASK32(64, 95, _bit, _bit);	\
    (_oword).u32[3] &= ~CI_BITFIELD_INPLACE_MASK32(96, 127, _bit, _bit); \
  } while (0)

#define CI_SET_QWORD32_BIT(_qword, _bit)				\
  do {									\
    (_qword).u32[0] |= CI_BITFIELD_INPLACE_MASK32(0, 31, _bit, _bit);	\
    (_qword).u32[1] |= CI_BITFIELD_INPLACE_MASK32(32, 63, _bit, _bit);	\
  } while (0)

#define CI_CLEAR_QWORD32_BIT(_qword, _bit)				\
  do {									\
    (_qword).u32[0] &= ~CI_BITFIELD_INPLACE_MASK32(0, 31, _bit, _bit);	\
    (_qword).u32[1] &= ~CI_BITFIELD_INPLACE_MASK32(32, 63, _bit, _bit);	\
  } while (0)

#define CI_SET_DWORD_BIT(_dword, _bit)					\
  do {									\
    (_dword).u32[0] |= CI_BITFIELD_INPLACE_MASK32(0, 31, _bit, _bit);	\
  } while (0)

#define CI_CLEAR_DWORD_BIT(_dword, _bit)				\
  do {									\
    (_dword).u32[0] &= ~CI_BITFIELD_INPLACE_MASK32(0, 31, _bit, _bit);	\
  } while (0)

/* Set bit field in a pre-populated structure */
#define CI_SET_OWORD_FIELD64(_oword, _field, _value)	\
  CI_SET_OWORD64(_oword, CI_BITFIELD_LOW_BIT(_field),	\
		 CI_BITFIELD_HIGH_BIT(_field), _value)

#define CI_SET_QWORD_FIELD64(_qword, _field, _value)	\
  CI_SET_QWORD64(_qword, CI_BITFIELD_LOW_BIT(_field),	\
		 CI_BITFIELD_HIGH_BIT(_field), _value)

#define CI_SET_OWORD_FIELD32(_oword, _field, _value)	\
  CI_SET_OWORD32(_oword, CI_BITFIELD_LOW_BIT(_field),	\
		 CI_BITFIELD_HIGH_BIT(_field), _value)

#define CI_SET_QWORD_FIELD32(_qword, _field, _value)	\
  CI_SET_QWORD32(_qword, CI_BITFIELD_LOW_BIT(_field),	\
		 CI_BITFIELD_HIGH_BIT(_field), _value)

#define CI_SET_DWORD_FIELD(_dword, _field, _value)	\
  CI_SET_DWORD32(_dword, CI_BITFIELD_LOW_BIT(_field),	\
		 CI_BITFIELD_HIGH_BIT(_field), _value)

/* Set/clear singel bit field in pre-populated structure */
#define CI_SET_OWORD_BIT_FIELD64(_oword, _field)		\
  CI_SET_OWORD_BIT64(_oword, CI_BITFIELD_LOW_BIT(_field))

#define CI_CLEAR_OWORD_BIT_FIELD64(_oword, _field)		\
  CI_CLEAR_OWORD_BIT64(_oword, CI_BITFIELD_LOW_BIT(_field))

#define CI_SET_QWORD_BIT_FIELD64(_qword, _field)		\
  CI_SET_QWORD_BIT64(_qword, CI_BITFIELD_LOW_BIT(_field))

#define CI_CLEAR_QWORD_BIT_FIELD64(_qword, _field)		\
  CI_CLEAR_QWORD_BIT64(_qword, CI_BITFIELD_LOW_BIT(_field))

#define CI_SET_OWORD_BIT_FIELD32(_oword, _field)		\
  CI_SET_OWORD_BIT32(_oword, CI_BITFIELD_LOW_BIT(_field))

#define CI_CLEAR_OWORD_BIT_FIELD32(_oword, _field)		\
  CI_CLEAR_OWORD_BIT32(_oword, CI_BITFIELD_LOW_BIT(_field))

#define CI_SET_QWORD_BIT_FIELD32(_qword, _field)		\
  CI_SET_QWORD_BIT32(_qword, CI_BITFIELD_LOW_BIT(_field))

#define CI_CLEAR_QWORD_BIT_FIELD32(_qword, _field)		\
  CI_CLEAR_QWORD_BIT32(_qword, CI_BITFIELD_LOW_BIT(_field))

#define CI_SET_DWORD_BIT_FIELD(_dword, _field)		\
  CI_SET_DWORD_BIT(_dword, CI_BITFIELD_LOW_BIT(_field))

#define CI_CLEAR_DWORD_BIT_FIELD(_dword, _field)		\
  CI_CLEAR_DWORD_BIT(_dword, CI_BITFIELD_LOW_BIT(_field))

#if CI_WORD_SIZE == 8
#define CI_SET_OWORD_FIELD CI_SET_OWORD_FIELD64
#define CI_SET_QWORD_FIELD CI_SET_QWORD_FIELD64
#define CI_SET_OWORD_BIT_FIELD CI_SET_OWORD_BIT64
#define CI_CLEAR_OWORD_BIT_FIELD CI_CLEAR_OWORD_BIT_FIELD64
#define CI_SET_QWORD_BIT_FIELD CI_SET_QWORD_BIT_FIELD64
#define CI_CLEAR_QWORD_BIT_FIELD CI_CLEAR_QWORD_BIT_FIELD64
#else
#define CI_SET_OWORD_FIELD CI_SET_OWORD_FIELD32
#define CI_SET_QWORD_FIELD CI_SET_QWORD_FIELD32
#define CI_SET_OWORD_BIT_FIELD CI_SET_OWORD_BIT32
#define CI_CLEAR_OWORD_BIT_FIELD CI_CLEAR_OWORD_BIT_FIELD32
#define CI_SET_QWORD_BIT_FIELD CI_SET_QWORD_BIT_FIELD32
#define CI_CLEAR_QWORD_BIT_FIELD CI_CLEAR_QWORD_BIT_FIELD32
#endif

#endif /* __CI_TOOLS_BITFIELD_H__ */
