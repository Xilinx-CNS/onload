/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __CI_COMPAT_BITFIELD_H__
#define __CI_COMPAT_BITFIELD_H__

/* This file s a light copy of bitfield.h header in linux_net */

#ifndef BITS_PER_LONG
#if defined(__x86_64__) || defined(__PPC64__) || defined (__aarch64__)
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif
#endif

/* Lowest bit numbers and widths */
#define CI_DUMMY_FIELD_LBN 0
#define CI_DUMMY_FIELD_WIDTH 0
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

/* Specified attribute (e.g. LBN) of the specified field */
#define CI_VAL(field, attribute) field ## _ ## attribute
/* Low bit number of the specified field */
#define CI_LOW_BIT(field) CI_VAL(field, LBN)
/* Bit width of the specified field */
#define CI_WIDTH(field) CI_VAL(field, WIDTH)
/* High bit number of the specified field */
#define CI_HIGH_BIT(field) (CI_LOW_BIT(field) + CI_WIDTH(field) - 1)

/* Mask equal in width to the specified field.
 *
 * For example, a field with width 5 would have a mask of 0x1f.
 *
 * The maximum width mask that can be generated is 64 bits.
 */
#define CI_MASK64(width)                        \
  ((width) == 64 ? ~((uint64_t) 0) :            \
   (((((uint64_t) 1) << (width))) - 1))

/* Mask equal in width to the specified field.
 *
 * For example, a field with width 5 would have a mask of 0x1f.
 *
 * The maximum width mask that can be generated is 32 bits.  Use
 * CI_MASK64 for higher width fields.
 */
#define CI_MASK32(width)                        \
  ((width) == 32 ? ~((uint32_t) 0) :            \
   (((((uint32_t) 1) << (width))) - 1))

#define ci_le64 uint64_t
#define ci_le32 uint32_t

typedef struct {
  ci_le64 b, a;
} ci_le128  __attribute__((aligned(16)));

/* A doubleword (i.e. 4 byte) datatype - little-endian in HW */
typedef union ci_dword {
  ci_le32 u32[1];
} ci_dword_t;

/* A quadword (i.e. 8 byte) datatype - little-endian in HW */
typedef union ci_qword {
  ci_le64 u64[1];
  ci_le32 u32[2];
  ci_dword_t dword[2];
} ci_qword_t;

/* An octword (eight-word, i.e. 16 byte) datatype - little-endian in HW */
typedef union ci_oword {
  ci_le128 u128;
  ci_le64 u64[2];
  ci_qword_t qword[2];
  ci_le32 u32[4];
  ci_dword_t dword[4];
} ci_oword_t;

/* Format string and value expanders for printk */
#define CI_DWORD_FMT "%08x"
#define CI_QWORD_FMT "%08x:%08x"
#define CI_OWORD_FMT "%08x:%08x:%08x:%08x"
#define CI_DWORD_VAL(dword)                     \
  ((unsigned int) le32_to_cpu((dword).u32[0]))
#define CI_QWORD_VAL(qword)                             \
  ((unsigned int) le32_to_cpu((qword).u32[1])),         \
    ((unsigned int) le32_to_cpu((qword).u32[0]))
#define CI_OWORD_VAL(oword)                             \
  ((unsigned int) le32_to_cpu((oword).u32[3])),         \
    ((unsigned int) le32_to_cpu((oword).u32[2])),       \
    ((unsigned int) le32_to_cpu((oword).u32[1])),       \
    ((unsigned int) le32_to_cpu((oword).u32[0]))

/*
 * Extract bit field portion [low,high) from the native-endian element
 * which contains bits [min,max).
 *
 * For example, suppose "element" represents the high 32 bits of a
 * 64-bit value, and we wish to extract the bits belonging to the bit
 * field occupying bits 28-45 of this 64-bit value.
 *
 * Then CI_EXTRACT ( element, 32, 63, 28, 45 ) would give
 *
 *   ( element ) << 4
 *
 * The result will contain the relevant bits filled in in the range
 * [0,high-low), with garbage in bits [high-low+1,...).
 */
#define CI_EXTRACT_NATIVE(native_element, min, max, low, high)  \
  ((low) > (max) || (high) < (min) ? 0 :                        \
   (low) > (min) ?                                              \
   (native_element) >> ((low) - (min)) :                        \
   (native_element) << ((min) - (low)))

/*
 * Extract bit field portion [low,high) from the 64-bit little-endian
 * element which contains bits [min,max)
 */
#define CI_EXTRACT64(element, min, max, low, high)              \
  CI_EXTRACT_NATIVE(le64_to_cpu(element), min, max, low, high)

/*
 * Extract bit field portion [low,high) from the 32-bit little-endian
 * element which contains bits [min,max)
 */
#define CI_EXTRACT32(element, min, max, low, high)              \
  CI_EXTRACT_NATIVE(le32_to_cpu(element), min, max, low, high)

#define CI_EXTRACT_OWORD64(oword, low, high)            \
  ((CI_EXTRACT64((oword).u64[0], 0, 63, low, high) |    \
    CI_EXTRACT64((oword).u64[1], 64, 127, low, high)) & \
   CI_MASK64((high) + 1 - (low)))

#define CI_EXTRACT_QWORD64(qword, low, high)            \
  (CI_EXTRACT64((qword).u64[0], 0, 63, low, high) &     \
   CI_MASK64((high) + 1 - (low)))

#define CI_EXTRACT_OWORD32(oword, low, high)            \
  ((CI_EXTRACT32((oword).u32[0], 0, 31, low, high) |    \
    CI_EXTRACT32((oword).u32[1], 32, 63, low, high) |   \
    CI_EXTRACT32((oword).u32[2], 64, 95, low, high) |   \
    CI_EXTRACT32((oword).u32[3], 96, 127, low, high)) & \
   CI_MASK32((high) + 1 - (low)))

#define CI_EXTRACT_QWORD32(qword, low, high)            \
  ((CI_EXTRACT32((qword).u32[0], 0, 31, low, high) |    \
    CI_EXTRACT32((qword).u32[1], 32, 63, low, high)) &  \
   CI_MASK32((high) + 1 - (low)))

#define CI_EXTRACT_DWORD(dword, low, high)              \
  (CI_EXTRACT32((dword).u32[0], 0, 31, low, high) &     \
   CI_MASK32((high) + 1 - (low)))

#define CI_OWORD_FIELD64(oword, field)          \
  CI_EXTRACT_OWORD64(oword, CI_LOW_BIT(field),  \
                     CI_HIGH_BIT(field))

#define CI_QWORD_FIELD64(qword, field)          \
  CI_EXTRACT_QWORD64(qword, CI_LOW_BIT(field),  \
                     CI_HIGH_BIT(field))

#define CI_OWORD_FIELD32(oword, field)          \
  CI_EXTRACT_OWORD32(oword, CI_LOW_BIT(field),  \
                     CI_HIGH_BIT(field))

#define CI_QWORD_FIELD32(qword, field)          \
  CI_EXTRACT_QWORD32(qword, CI_LOW_BIT(field),  \
                     CI_HIGH_BIT(field))

#define CI_DWORD_FIELD(dword, field)            \
  CI_EXTRACT_DWORD(dword, CI_LOW_BIT(field),    \
                   CI_HIGH_BIT(field))

#define CI_OWORD_IS_ZERO64(oword)                       \
  (((oword).u64[0] | (oword).u64[1]) == (ci_le64) 0)

#define CI_QWORD_IS_ZERO64(qword)               \
  (((qword).u64[0]) == (ci_le64) 0)

#define CI_OWORD_IS_ZERO32(oword)                                       \
  (((oword).u32[0] | (oword).u32[1] | (oword).u32[2] | (oword).u32[3])  \
   == (ci_le32) 0)

#define CI_QWORD_IS_ZERO32(qword)                       \
  (((qword).u32[0] | (qword).u32[1]) == (ci_le32) 0)

#define CI_DWORD_IS_ZERO(dword)                 \
  (((dword).u32[0]) == (ci_le32) 0)

#define CI_OWORD_IS_ALL_ONES64(oword)                   \
  (((oword).u64[0] & (oword).u64[1]) == ~((ci_le64) 0))

#define CI_QWORD_IS_ALL_ONES64(qword)           \
  ((qword).u64[0] == ~((ci_le64) 0))

#define CI_OWORD_IS_ALL_ONES32(oword)                                   \
  (((oword).u32[0] & (oword).u32[1] & (oword).u32[2] & (oword).u32[3])  \
   == ~((ci_le32) 0))

#define CI_QWORD_IS_ALL_ONES32(qword)                   \
  (((qword).u32[0] & (qword).u32[1]) == ~((ci_le32) 0))

#define CI_DWORD_IS_ALL_ONES(dword)             \
  ((dword).u32[0] == ~((ci_le32) 0))

#if BITS_PER_LONG == 64
#define CI_OWORD_FIELD    CI_OWORD_FIELD64
#define CI_QWORD_FIELD    CI_QWORD_FIELD64
#define CI_OWORD_IS_ZERO  CI_OWORD_IS_ZERO64
#define CI_QWORD_IS_ZERO  CI_QWORD_IS_ZERO64
#define CI_OWORD_IS_ALL_ONES  CI_OWORD_IS_ALL_ONES64
#define CI_QWORD_IS_ALL_ONES  CI_QWORD_IS_ALL_ONES64
#else
#define CI_OWORD_FIELD    CI_OWORD_FIELD32
#define CI_QWORD_FIELD    CI_QWORD_FIELD32
#define CI_OWORD_IS_ZERO  CI_OWORD_IS_ZERO32
#define CI_QWORD_IS_ZERO  CI_QWORD_IS_ZERO32
#define CI_OWORD_IS_ALL_ONES  CI_OWORD_IS_ALL_ONES32
#define CI_QWORD_IS_ALL_ONES  CI_QWORD_IS_ALL_ONES32
#endif

/*
 * Construct bit field portion
 *
 * Creates the portion of the bit field [low,high) that lies within
 * the range [min,max).
 */
#define CI_INSERT_NATIVE64(min, max, low, high, value)  \
  (((low > max) || (high < min)) ? 0 :                  \
   ((low > min) ?                                       \
    (((uint64_t) (value)) << (low - min)) :             \
    (((uint64_t) (value)) >> (min - low))))

#define CI_INSERT_NATIVE32(min, max, low, high, value)  \
  (((low > max) || (high < min)) ? 0 :                  \
   ((low > min) ?                                       \
    (((uint32_t) (value)) << (low - min)) :             \
    (((uint32_t) (value)) >> (min - low))))

#define CI_INSERT_NATIVE(min, max, low, high, value)    \
  ((((max - min) >= 32) || ((high - low) >= 32)) ?      \
   CI_INSERT_NATIVE64(min, max, low, high, value) :     \
   CI_INSERT_NATIVE32(min, max, low, high, value))

/*
 * Construct bit field portion
 *
 * Creates the portion of the named bit field that lies within the
 * range [min,max).
 */
#define CI_INSERT_FIELD_NATIVE(min, max, field, value)  \
  CI_INSERT_NATIVE(min, max, CI_LOW_BIT(field),         \
                   CI_HIGH_BIT(field), value)

/*
 * Construct bit field
 *
 * Creates the portion of the named bit fields that lie within the
 * range [min,max).
 */
#define CI_INSERT_FIELDS_NATIVE(min, max,                       \
                                field1, value1,                 \
                                field2, value2,                 \
                                field3, value3,                 \
                                field4, value4,                 \
                                field5, value5,                 \
                                field6, value6,                 \
                                field7, value7,                 \
                                field8, value8,                 \
                                field9, value9,                 \
                                field10, value10,               \
                                field11, value11)               \
  (CI_INSERT_FIELD_NATIVE((min), (max), field1, (value1)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field2, (value2)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field3, (value3)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field4, (value4)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field5, (value5)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field6, (value6)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field7, (value7)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field8, (value8)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field9, (value9)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field10, (value10)) |     \
   CI_INSERT_FIELD_NATIVE((min), (max), field11, (value11)))

#define CI_INSERT_FIELDS64(...)                         \
  cpu_to_le64(CI_INSERT_FIELDS_NATIVE(__VA_ARGS__))

#define CI_INSERT_FIELDS32(...)                         \
  cpu_to_le32(CI_INSERT_FIELDS_NATIVE(__VA_ARGS__))

#define CI_POPULATE_OWORD64(oword, ...) do {                    \
    (oword).u64[0] = CI_INSERT_FIELDS64(0, 63, __VA_ARGS__);    \
    (oword).u64[1] = CI_INSERT_FIELDS64(64, 127, __VA_ARGS__);  \
  } while (0)

#define CI_POPULATE_QWORD64(qword, ...) do {                    \
    (qword).u64[0] = CI_INSERT_FIELDS64(0, 63, __VA_ARGS__);    \
  } while (0)

#define CI_POPULATE_OWORD32(oword, ...) do {                            \
    (oword).u32[0] = (uint32_t)CI_INSERT_FIELDS32(0, 31, __VA_ARGS__);  \
    (oword).u32[1] = (uint32_t)CI_INSERT_FIELDS32(32, 63, __VA_ARGS__); \
    (oword).u32[2] = (uint32_t)CI_INSERT_FIELDS32(64, 95, __VA_ARGS__); \
    (oword).u32[3] = (uint32_t)CI_INSERT_FIELDS32(96, 127, __VA_ARGS__); \
  } while (0)

#define CI_POPULATE_QWORD32(qword, ...) do {                            \
    (qword).u32[0] = (uint32_t)CI_INSERT_FIELDS32(0, 31, __VA_ARGS__);  \
    (qword).u32[1] = (uint32_t)CI_INSERT_FIELDS32(32, 63, __VA_ARGS__); \
  } while (0)

#define CI_POPULATE_DWORD(dword, ...) do {                      \
    (dword).u32[0] = CI_INSERT_FIELDS32(0, 31, __VA_ARGS__);    \
  } while (0)

#if BITS_PER_LONG == 64
#define CI_POPULATE_OWORD CI_POPULATE_OWORD64
#define CI_POPULATE_QWORD CI_POPULATE_QWORD64
#else
#define CI_POPULATE_OWORD CI_POPULATE_OWORD32
#define CI_POPULATE_QWORD CI_POPULATE_QWORD32
#endif

/* Populate an octword field with various numbers of arguments */
#define CI_POPULATE_OWORD_11 CI_POPULATE_OWORD
#define CI_POPULATE_OWORD_10(oword, ...)                         \
  CI_POPULATE_OWORD_11(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_9(oword, ...)                         \
  CI_POPULATE_OWORD_10(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_8(oword, ...)                         \
  CI_POPULATE_OWORD_9(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_7(oword, ...)                         \
  CI_POPULATE_OWORD_8(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_6(oword, ...)                         \
  CI_POPULATE_OWORD_7(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_5(oword, ...)                         \
  CI_POPULATE_OWORD_6(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_4(oword, ...)                         \
  CI_POPULATE_OWORD_5(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_3(oword, ...)                         \
  CI_POPULATE_OWORD_4(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_2(oword, ...)                         \
  CI_POPULATE_OWORD_3(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_OWORD_1(oword, ...)                         \
  CI_POPULATE_OWORD_2(oword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_ZERO_OWORD(oword)                    \
  CI_POPULATE_OWORD_1(oword, CI_DUMMY_FIELD, 0)
#define CI_SET_OWORD(oword)                     \
  CI_POPULATE_OWORD_4(oword,                    \
                      CI_DWORD_0, 0xffffffff,   \
                      CI_DWORD_1, 0xffffffff,   \
                      CI_DWORD_2, 0xffffffff,   \
                      CI_DWORD_3, 0xffffffff)

/* Populate a quadword field with various numbers of arguments */
#define CI_POPULATE_QWORD_11 CI_POPULATE_QWORD
#define CI_POPULATE_QWORD_10(qword, ...)                         \
  CI_POPULATE_QWORD_11(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_9(qword, ...)                         \
  CI_POPULATE_QWORD_10(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_8(qword, ...)                         \
  CI_POPULATE_QWORD_9(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_7(qword, ...)                         \
  CI_POPULATE_QWORD_8(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_6(qword, ...)                         \
  CI_POPULATE_QWORD_7(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_5(qword, ...)                         \
  CI_POPULATE_QWORD_6(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_4(qword, ...)                         \
  CI_POPULATE_QWORD_5(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_3(qword, ...)                         \
  CI_POPULATE_QWORD_4(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_2(qword, ...)                         \
  CI_POPULATE_QWORD_3(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_QWORD_1(qword, ...)                         \
  CI_POPULATE_QWORD_2(qword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_ZERO_QWORD(qword)                    \
  CI_POPULATE_QWORD_1(qword, CI_DUMMY_FIELD, 0)
#define CI_SET_QWORD(qword)                     \
  CI_POPULATE_QWORD_2(qword,                    \
                      CI_DWORD_0, 0xffffffff,   \
                      CI_DWORD_1, 0xffffffff)

/* Populate a dword field with various numbers of arguments */
#define CI_POPULATE_DWORD_11 CI_POPULATE_DWORD
#define CI_POPULATE_DWORD_10(dword, ...)                         \
  CI_POPULATE_DWORD_11(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_9(dword, ...)                         \
  CI_POPULATE_DWORD_10(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_8(dword, ...)                         \
  CI_POPULATE_DWORD_9(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_7(dword, ...)                         \
  CI_POPULATE_DWORD_8(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_6(dword, ...)                         \
  CI_POPULATE_DWORD_7(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_5(dword, ...)                         \
  CI_POPULATE_DWORD_6(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_4(dword, ...)                         \
  CI_POPULATE_DWORD_5(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_3(dword, ...)                         \
  CI_POPULATE_DWORD_4(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_2(dword, ...)                         \
  CI_POPULATE_DWORD_3(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_POPULATE_DWORD_1(dword, ...)                         \
  CI_POPULATE_DWORD_2(dword, CI_DUMMY_FIELD, 0, __VA_ARGS__)
#define CI_ZERO_DWORD(dword)                    \
  CI_POPULATE_DWORD_1(dword, CI_DUMMY_FIELD, 0)
#define CI_SET_DWORD(dword)                             \
  CI_POPULATE_DWORD_1(dword, CI_DWORD_0, 0xffffffff)

/*
 * Modify a named field within an already-populated structure.  Used
 * for read-modify-write operations.
 *
 */
#define CI_INVERT_OWORD(oword) do {             \
    (oword).u64[0] = ~((oword).u64[0]);         \
    (oword).u64[1] = ~((oword).u64[1]);         \
  } while (0)

#define CI_AND_OWORD(oword, from, mask)                 \
  do {                                                  \
    (oword).u64[0] = (from).u64[0] & (mask).u64[0];     \
    (oword).u64[1] = (from).u64[1] & (mask).u64[1];     \
  } while (0)

#define CI_OR_OWORD(oword, from, mask)                  \
  do {                                                  \
    (oword).u64[0] = (from).u64[0] | (mask).u64[0];     \
    (oword).u64[1] = (from).u64[1] | (mask).u64[1];     \
  } while (0)

#define CI_INSERT64(min, max, low, high, value)                 \
  cpu_to_le64(CI_INSERT_NATIVE(min, max, low, high, value))

#define CI_INSERT32(min, max, low, high, value)                 \
  cpu_to_le32(CI_INSERT_NATIVE(min, max, low, high, value))

#define CI_INPLACE_MASK64(min, max, low, high)                          \
  CI_INSERT64(min, max, low, high, CI_MASK64((high) + 1 - (low)))

#define CI_INPLACE_MASK32(min, max, low, high)                          \
  CI_INSERT32(min, max, low, high, CI_MASK32((high) + 1 - (low)))

#define CI_SET_OWORD64(oword, low, high, value) do {                    \
    (oword).u64[0] = (((oword).u64[0]                                   \
                       & ~CI_INPLACE_MASK64(0,  63, low, high))         \
                      | CI_INSERT64(0,  63, low, high, value));         \
    (oword).u64[1] = (((oword).u64[1]                                   \
                       & ~CI_INPLACE_MASK64(64, 127, low, high))        \
                      | CI_INSERT64(64, 127, low, high, value));        \
  } while (0)

#define CI_SET_QWORD64(qword, low, high, value) do {            \
    (qword).u64[0] = (((qword).u64[0]                           \
                       & ~CI_INPLACE_MASK64(0, 63, low, high))  \
                      | CI_INSERT64(0, 63, low, high, value));  \
  } while (0)

#define CI_SET_OWORD32(oword, low, high, value) do {                    \
    (oword).u32[0] = (((oword).u32[0]                                   \
                       & ~CI_INPLACE_MASK32(0, 31, low, high))          \
                      | CI_INSERT32(0, 31, low, high, value));          \
    (oword).u32[1] = (((oword).u32[1]                                   \
                       & ~CI_INPLACE_MASK32(32, 63, low, high))         \
                      | CI_INSERT32(32, 63, low, high, value));         \
    (oword).u32[2] = (((oword).u32[2]                                   \
                       & ~CI_INPLACE_MASK32(64, 95, low, high))         \
                      | CI_INSERT32(64, 95, low, high, value));         \
    (oword).u32[3] = (((oword).u32[3]                                   \
                       & ~CI_INPLACE_MASK32(96, 127, low, high))        \
                      | CI_INSERT32(96, 127, low, high, value));        \
  } while (0)

#define CI_SET_QWORD32(qword, low, high, value) do {            \
    (qword).u32[0] = (((qword).u32[0]                           \
                       & ~CI_INPLACE_MASK32(0, 31, low, high))  \
                      | CI_INSERT32(0, 31, low, high, value));  \
    (qword).u32[1] = (((qword).u32[1]                           \
                       & ~CI_INPLACE_MASK32(32, 63, low, high)) \
                      | CI_INSERT32(32, 63, low, high, value)); \
  } while (0)

#define CI_SET_DWORD32(dword, low, high, value) do {            \
    (dword).u32[0] = (((dword).u32[0]                           \
                       & ~CI_INPLACE_MASK32(0, 31, low, high))  \
                      | CI_INSERT32(0, 31, low, high, value));  \
  } while (0)

#define CI_SET_OWORD_FIELD64(oword, field, value)       \
  CI_SET_OWORD64(oword, CI_LOW_BIT(field),              \
                 CI_HIGH_BIT(field), value)

#define CI_SET_QWORD_FIELD64(qword, field, value)       \
  CI_SET_QWORD64(qword, CI_LOW_BIT(field),              \
                 CI_HIGH_BIT(field), value)

#define CI_SET_OWORD_FIELD32(oword, field, value)       \
  CI_SET_OWORD32(oword, CI_LOW_BIT(field),              \
                 CI_HIGH_BIT(field), value)

#define CI_SET_QWORD_FIELD32(qword, field, value)       \
  CI_SET_QWORD32(qword, CI_LOW_BIT(field),              \
                 CI_HIGH_BIT(field), value)

#define CI_SET_DWORD_FIELD(dword, field, value) \
  CI_SET_DWORD32(dword, CI_LOW_BIT(field),      \
                 CI_HIGH_BIT(field), value)



#if BITS_PER_LONG == 64
#define CI_SET_OWORD_FIELD CI_SET_OWORD_FIELD64
#define CI_SET_QWORD_FIELD CI_SET_QWORD_FIELD64
#else
#define CI_SET_OWORD_FIELD CI_SET_OWORD_FIELD32
#define CI_SET_QWORD_FIELD CI_SET_QWORD_FIELD32
#endif

/* Used to avoid compiler warnings about shift range exceeding width
 * of the data types when dma_addr_t is only 32 bits wide.
 */
#define DMA_ADDR_T_WIDTH  (8 * sizeof(dma_addr_t))
#define CI_DMA_TYPE_WIDTH(width)                                \
  (((width) < DMA_ADDR_T_WIDTH) ? (width) : DMA_ADDR_T_WIDTH)


/* Static initialiser */
#define CI_OWORD32(a, b, c, d)                  \
  { .u32 = { cpu_to_le32(a), cpu_to_le32(b),    \
             cpu_to_le32(c), cpu_to_le32(d) } }

#endif /* __CI_COMPAT_BITFIELD_H__ */
