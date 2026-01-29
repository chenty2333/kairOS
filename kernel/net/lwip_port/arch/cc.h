/**
 * arch/cc.h - lwIP compiler/platform abstraction for Kairos
 */

#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <kairos/types.h>
#include <kairos/printk.h>

/* Type definitions matching lwIP expectations */
typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;
typedef uintptr_t mem_ptr_t;

/* Prevent lwIP from including headers not available in freestanding kernel */
#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_UNISTD_H   1
#define LWIP_NO_CTYPE_H    1
#define LWIP_NO_LIMITS_H   1

/* ssize_t is already defined in kairos/types.h; prevent lwIP from redefining */
#define SSIZE_MAX 0x7FFFFFFFFFFFFFFFL

/* Printf format specifiers */
#define X8_F  "02x"
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "lu"

/* Compiler hints */
#define LWIP_PLATFORM_DIAG(x) do { printk x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { \
    printk("lwip assert: %s at %s:%d\n", (x), __FILE__, __LINE__); \
    for (;;); \
} while (0)

/* Byte order - RISC-V is little-endian */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* Structure packing */
#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

/* Random number */
u32_t lwip_kairos_rand(void);
#define LWIP_RAND() lwip_kairos_rand()

/* No errno.h in kernel */
#define LWIP_PROVIDE_ERRNO 0
#define LWIP_ERRNO_STDINCLUDE 0

#endif /* LWIP_ARCH_CC_H */
