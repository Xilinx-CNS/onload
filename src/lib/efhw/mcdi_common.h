/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2019 Xilinx, Inc. */

#ifndef LIB_EFHW_MCDI_COMMMON_H
#define LIB_EFHW_MCDI_COMMMON_H

#include <ci/compat.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/bitfield.h>
#include <ci/tools/sysdep.h>


extern bool check_supported_filter(const ci_dword_t* matches, unsigned filter);
extern uint64_t mcdi_parser_info_to_filter_flags(ci_dword_t *out);
extern uint64_t mcdi_capability_info_to_nic_flags(ci_dword_t *out,
                                                  size_t out_size);

#ifndef BUILD_BUG_ON_ZERO
        #define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef DIV_ROUND_UP    
        #define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

ci_inline void __efhw_mcdi_raw_writel(ci_uint32 data, char *addr)
{       
        *(ci_uint32*) addr = data;
}                      
ci_inline void efhw_mcdi_writel(ci_uint32 data, char *addr)
{               
        __efhw_mcdi_raw_writel(CI_BSWAP_LE32(data), (addr));
}                      

ci_inline void __efhw_mcdi_raw_write(ci_uint16 data, char *addr)
{
        *(ci_uint16*) addr = data;
}
ci_inline void efhw_mcdi_write(ci_uint16 data, char *addr)
{
        __efhw_mcdi_raw_write(CI_BSWAP_LE16(data), (addr));
}

ci_inline ci_uint32 __efhw_mcdi_raw_readl(char *addr) 
{
        return *(ci_uint32*) addr;
}
ci_inline ci_uint32 efhw_mcdi_readl(char *addr)
{
        ci_uint32 x = __efhw_mcdi_raw_readl(addr);
        return CI_BSWAP_LE32(x);
}

ci_inline ci_uint16 __efhw_mcdi_raw_read(char *addr) 
{
        return *(ci_uint16*) addr;
}
ci_inline ci_uint16 efhw_mcdi_read(char *addr)
{
        ci_uint16 x = __efhw_mcdi_raw_read(addr);
        return CI_BSWAP_LE16(x);
}

/* We expect that 16- and 32-bit fields in MCDI requests and responses
 * are appropriately aligned, but 64-bit fields are only
 * 32-bit-aligned.
 *
 * In the following:
 * WORD  == 16 bits
 * DWORD == 32 bits
 * QWORD == 64 bits
 */
#define _EFHW_MCDI_CHECK_ALIGN(_ofst, _align)				\
	((_ofst) + BUILD_BUG_ON_ZERO((_ofst) & (_align - 1)))

#define _EFHW_MCDI_PTR(_buf, _offset)					\
	((u8 *)(_buf) + (_offset))

#define _EFHW_MCDI_ARRAY_PTR(_buf, _field, _index, _align)		\
	(_EFHW_MCDI_PTR((_buf),						\
	_EFHW_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _OFST , 		\
			       (_align))) +				\
	(_index) * _EFHW_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _LEN, (_align)))

#define _EFHW_MCDI_ARRAY_QWORD_PTR(_buf, _field, _dword, _index, _align)\
	(_EFHW_MCDI_PTR((_buf),						\
	_EFHW_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _dword ## _OFST , 	\
			       (_align))) +				\
	(_index) * _EFHW_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _LEN, (_align)))

#define _EFHW_MCDI_ARRAY_DWORD(_buf, _field, _index)			\
	(BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 4) +		\
	 _EFHW_MCDI_ARRAY_PTR(_buf, _field, _index, 4))

#define _EFHW_MCDI_ARRAY_QWORD(_buf, _field, _dword, _index)		\
	(BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 8) +		\
	_EFHW_MCDI_ARRAY_QWORD_PTR((_buf), _field, _dword, (_index), 4))

#define _EFHW_MCDI_DWORD_FIELD(_buf, _field)				\
	((u8 *)(_buf) + (_EFHW_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _OFST, 4)))

#define _EFHW_MCDI_WORD_FIELD(_buf, _field)				\
	((u8 *)(_buf) + (_EFHW_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _OFST, 2)))

#define EFHW_MCDI_PTR(_buf, _field)					\
	_EFHW_MCDI_PTR(_buf, MC_CMD_ ## _field ## _OFST)

#define EFHW_MCDI_DECLARE_BUF(_name, _len)				\
	ci_dword_t _name[DIV_ROUND_UP((_len), 4)]

#define EFHW_MCDI_INITIALISE_BUF_SIZE(_name, _name_size)		\
	memset(_name, 0, _name_size)

#define EFHW_MCDI_INITIALISE_BUF(_name)				\
	EFHW_MCDI_INITIALISE_BUF_SIZE(_name, sizeof(_name))

#define EFHW_MCDI_QWORD(_buf, _field)					\
	(efhw_mcdi_readl(_EFHW_MCDI_DWORD_FIELD((_buf), _field)) | \
	 (u64)efhw_mcdi_readl(_EFHW_MCDI_DWORD_FIELD((_buf), _field) + 4) << 32)

#define EFHW_MCDI_DWORD(_buf, _field)					\
	efhw_mcdi_readl(_EFHW_MCDI_DWORD_FIELD((_buf), _field))

#define EFHW_MCDI_WORD(_buf, _field)					\
	efhw_mcdi_read(_EFHW_MCDI_WORD_FIELD((_buf), _field))

#define EFHW_MCDI_BYTE(_buf, _field)					\
	efhw_mcdi_read(EFHW_MCDI_PTR((_buf), _field))

#define EFHW_MCDI_SET_WORD(_buf, _field, _value)			\
	efhw_mcdi_write((_value), _EFHW_MCDI_WORD_FIELD((_buf), _field))

#define EFHW_MCDI_SET_DWORD(_buf, _field, _value)			\
	efhw_mcdi_writel((_value), _EFHW_MCDI_DWORD_FIELD((_buf), _field))

#define EFHW_MCDI_SET_QWORD(_buf, _field, _value)			\
	do {								\
		efhw_mcdi_writel(((u32)(_value)),			\
			_EFHW_MCDI_DWORD_FIELD((_buf), _field ## _LO ));\
		efhw_mcdi_writel(((u64)(_value) >> 32),			\
			_EFHW_MCDI_DWORD_FIELD((_buf), _field ## _HI ));\
	} while (0)

#define EFHW_MCDI_SET_ARRAY_DWORD(_buf, _field, _index, _value)		\
	do {								\
		efhw_mcdi_writel(((u32)(_value)), 			\
			(u8 *)_EFHW_MCDI_ARRAY_DWORD(			\
				(_buf), _field, (_index)));	\
        } while (0)

#define EFHW_MCDI_SET_ARRAY_QWORD(_buf, _field, _index, _value)		\
	do {								\
		efhw_mcdi_writel(((u32)(_value)), 			\
			(u8 *)_EFHW_MCDI_ARRAY_QWORD(			\
				(_buf), _field, _LO, (_index)));	\
		efhw_mcdi_writel(((u64)(_value) >> 32), 		\
			(u8 *)_EFHW_MCDI_ARRAY_QWORD(			\
				(_buf), _field, _HI, (_index)));	\
        } while (0)

#define EFHW_MCDI_VAR_ARRAY_LEN(_len, _field)				\
	min_t(size_t, MC_CMD_ ## _field ## _MAXNUM,			\
	      ((_len) - MC_CMD_ ## _field ## _OFST) / MC_CMD_ ## _field ## _LEN)

#define EFHW_MCDI_ARRAY_DWORD(_buf, _field, _index)			\
	efhw_mcdi_readl(_EFHW_MCDI_ARRAY_DWORD(_buf, _field, _index))

#define _EFHW_MCDI_DWORD(_buf, _field)                                       \
        ((_buf) + (_EFHW_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _OFST, 4) >> 2))

#define EFHW_MCDI_POPULATE_DWORD_1(_buf, _field, _name1, _value1)        \
	CI_POPULATE_DWORD_1(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1)
#define EFHW_MCDI_POPULATE_DWORD_2(_buf, _field, _name1, _value1,        \
				   _name2, _value2)                      \
	CI_POPULATE_DWORD_2(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2)
#define EFHW_MCDI_POPULATE_DWORD_3(_buf, _field, _name1, _value1,        \
				   _name2, _value2, _name3, _value3)     \
	CI_POPULATE_DWORD_3(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2,\
					      MC_CMD_ ## _name3, _value3)
#define EFHW_MCDI_POPULATE_DWORD_4(_buf, _field, _name1, _value1,        \
				   _name2, _value2, _name3, _value3,     \
				   _name4, _value4)                      \
	CI_POPULATE_DWORD_4(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2,\
					      MC_CMD_ ## _name3, _value3,\
					      MC_CMD_ ## _name4, _value4)
#define EFHW_MCDI_POPULATE_DWORD_5(_buf, _field, _name1, _value1,        \
				   _name2, _value2, _name3, _value3,     \
				   _name4, _value4, _name5, _value5)     \
	CI_POPULATE_DWORD_5(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2,\
					      MC_CMD_ ## _name3, _value3,\
					      MC_CMD_ ## _name4, _value4,\
					      MC_CMD_ ## _name5, _value5)
#define EFHW_MCDI_POPULATE_DWORD_6(_buf, _field, _name1, _value1,        \
				   _name2, _value2, _name3, _value3,     \
				   _name4, _value4, _name5, _value5,     \
				   _name6, _value6)                      \
	CI_POPULATE_DWORD_6(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2,\
					      MC_CMD_ ## _name3, _value3,\
					      MC_CMD_ ## _name4, _value4,\
					      MC_CMD_ ## _name5, _value5,\
					      MC_CMD_ ## _name6, _value6)
#define EFHW_MCDI_POPULATE_DWORD_7(_buf, _field, _name1, _value1,        \
				   _name2, _value2, _name3, _value3,     \
				   _name4, _value4, _name5, _value5,     \
				   _name6, _value6, _name7, _value7)     \
	CI_POPULATE_DWORD_7(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2,\
					      MC_CMD_ ## _name3, _value3,\
					      MC_CMD_ ## _name4, _value4,\
					      MC_CMD_ ## _name5, _value5,\
					      MC_CMD_ ## _name6, _value6,\
					      MC_CMD_ ## _name7, _value7)
#define EFHW_MCDI_POPULATE_DWORD_8(_buf, _field, _name1, _value1,        \
				   _name2, _value2, _name3, _value3,     \
				   _name4, _value4, _name5, _value5,     \
				   _name6, _value6, _name7, _value7,     \
				   _name8, _value8)                      \
	CI_POPULATE_DWORD_8(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2,\
					      MC_CMD_ ## _name3, _value3,\
					      MC_CMD_ ## _name4, _value4,\
					      MC_CMD_ ## _name5, _value5,\
					      MC_CMD_ ## _name6, _value6,\
					      MC_CMD_ ## _name7, _value7,\
					      MC_CMD_ ## _name8, _value8)
#define EFHW_MCDI_POPULATE_DWORD_9(_buf, _field, _name1, _value1,        \
				   _name2, _value2, _name3, _value3,     \
				   _name4, _value4, _name5, _value5,     \
				   _name6, _value6, _name7, _value7,     \
				   _name8, _value8, _name9, _value9)     \
	CI_POPULATE_DWORD_9(*_EFHW_MCDI_DWORD(_buf, _field),             \
					      MC_CMD_ ## _name1, _value1,\
					      MC_CMD_ ## _name2, _value2,\
					      MC_CMD_ ## _name3, _value3,\
					      MC_CMD_ ## _name4, _value4,\
					      MC_CMD_ ## _name5, _value5,\
					      MC_CMD_ ## _name6, _value6,\
					      MC_CMD_ ## _name7, _value7,\
					      MC_CMD_ ## _name8, _value8,\
					      MC_CMD_ ## _name9, _value9)

#define EFHW_MCDI_POPULATE_DWORD_10(_buf, _field, _name1, _value1,	\
				    _name2, _value2, _name3, _value3,	\
				    _name4, _value4, _name5, _value5,	\
				    _name6, _value6, _name7, _value7,	\
				    _name8, _value8, _name9, _value9,	\
				    _name10, _value10)			\
	CI_POPULATE_DWORD_10(*_EFHW_MCDI_DWORD(_buf, _field),             \
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4,		\
			     MC_CMD_ ## _name5, _value5,		\
			     MC_CMD_ ## _name6, _value6,		\
			     MC_CMD_ ## _name7, _value7,		\
			     MC_CMD_ ## _name8, _value8,		\
			     MC_CMD_ ## _name9, _value9,		\
			     MC_CMD_ ## _name10, _value10)

#define EFHW_MCDI_POPULATE_DWORD_11(_buf, _field, _name1, _value1,	\
				    _name2, _value2, _name3, _value3,	\
				    _name4, _value4, _name5, _value5,	\
				    _name6, _value6, _name7, _value7,	\
				    _name8, _value8, _name9, _value9,	\
				    _name10, _value10, _name11, _value11) \
	CI_POPULATE_DWORD_11(*_EFHW_MCDI_DWORD(_buf, _field),             \
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4,		\
			     MC_CMD_ ## _name5, _value5,		\
			     MC_CMD_ ## _name6, _value6,		\
			     MC_CMD_ ## _name7, _value7,		\
			     MC_CMD_ ## _name8, _value8,		\
			     MC_CMD_ ## _name9, _value9,		\
			     MC_CMD_ ## _name10, _value10,		\
			     MC_CMD_ ## _name11, _value11)

#define EFHW_MCDI_DWORD_FIELD(_buf, _name) \
  ((EFHW_MCDI_DWORD(_buf, _name) >> (MC_CMD_ ## _name ## _LBN)) \
   & ((1 << (MC_CMD_ ## _name ## _WIDTH)) - 1))


#define EFHW_MCDI_MATCH_FIELD_BIT(type) \
  (1 << MC_CMD_FILTER_OP_IN_MATCH_ ## type ## _LBN)

#endif /* LIB_EFHW_MCDI_COMMMON_H */
