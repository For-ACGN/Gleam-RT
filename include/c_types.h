#ifndef C_TYPES_H
#define C_TYPES_H

// reference basic types from Go
typedef char      int8;
typedef short     int16;
typedef int       int32;
typedef long long int64;

typedef unsigned char      uint8;
typedef unsigned short     uint16;
typedef unsigned int       uint32;
typedef unsigned long long uint64;

#ifdef _WIN64
    typedef int64  integer;
    typedef uint64 uint;
    typedef uint64 uintptr;
#elif _WIN32
    typedef int32  integer;
    typedef uint32 uint;
    typedef uint32 uintptr;
#endif

typedef float  float32;
typedef double float64;

typedef unsigned char byte;
typedef int32         rune;

typedef _Bool bool;
#define true  1
#define false 0

#ifndef NULL
#define NULL 0
#endif

// copy from <stdint.h>
#define INT8_MIN   (-127i8 - 1)
#define INT16_MIN  (-32767i16 - 1)
#define INT32_MIN  (-2147483647i32 - 1)
#define INT64_MIN  (-9223372036854775807i64 - 1)
#define INT8_MAX   127i8
#define INT16_MAX  32767i16
#define INT32_MAX  2147483647i32
#define INT64_MAX  9223372036854775807i64
#define UINT8_MAX  0xFFui8
#define UINT16_MAX 0xFFFFui16
#define UINT32_MAX 0xFFFFFFFFui32
#define UINT64_MAX 0xFFFFFFFFFFFFFFFFui64

// calculate the array length
#ifndef arrlen
#define arrlen(array) (sizeof(array) / sizeof(array[0]))
#endif

// calculate the structure field offset of the structure
#ifndef offsetof
#define offsetof(struct, field) ((uintptr) & (((struct*)0)->field))
#endif

// calculate ACSII string length.
static uint strlen_a(byte* s)
{
    uint l = 0;
    for (;;)
    {
        if (*s == 0x00)
        {
            break;
        }
        l++;
        s++;
    }
    return l;
}

// calculate Unicode string length.
static uint strlen_w(byte* s)
{
    uint l = 0;
    for (;;)
    {
        byte b0 = *(s + 0);
        byte b1 = *(s + 1);
        if (b0 == 0x00 && b1 == 0x00)
        {
            break;
        }
        l++;
        s += 2;
    }
    return l;
}

typedef void* (*malloc_t )(uint size);
typedef void* (*realloc_t)(void* address, uint size);
typedef bool  (*free_t   )(void* address);

// mem_equal is used to compare the memory is equal.
static bool mem_equal(void* dst, void* src, uint size)
{
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    for (uint i = 0; i < size; i++)
    {
        if (*d != *s)
        {
            return false;
        }
        d++;
        s++;
    }
    return true;
}

// mem_zero is used to check the destination memory are all zero.
static bool mem_zero(void* dst, uint size)
{
    byte* d = (byte*)dst;
    for (uint i = 0; i < size; i++)
    {
        if (*d != NULL)
        {
            return false;
        }
        d++;
    }
    return true;
}

// mem_copy is used to copy source memory data to the destination.
static void mem_copy(void* dst, void* src, uint size)
{
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    for (uint i = 0; i < size; i++)
    {
        *d = *s;
        d++;
        s++;
    }
}

// mem_set is used to fill the memory with value.
static void mem_set(void* ptr, byte val, uint num)
{
    byte* addr = (byte*)ptr;
    for (uint i = 0; i < num; i++)
    {
        *addr = val;
        addr++;
    }
}

// mem_clean is used to fill the memory with zero.
static void mem_clean(void* ptr, uint num)
{
    mem_set(ptr, 0, num);
}

#endif // C_TYPES_H
