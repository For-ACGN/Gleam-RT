#ifndef LIB_STRING_H
#define LIB_STRING_H

#include "c_types.h"

typedef byte*   ascii;
typedef uint16* utf16;

// strlen_a is used to calculate ACSII string length.
uint strlen_a(ascii s);

// strlen_w is used to calculate Unicode string length.
uint strlen_w(utf16 s);

// strcmp_a is used to compare two ACSII strings.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strcmp_a(ascii a, ascii b);

// strcmp_w is used to compare two Unicode strings.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strcmp_w(utf16 a, utf16 b);

// strncmp_a is used to compare two ACSII strings with length.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strncmp_a(ascii a, ascii b, int64 n);

// strncmp_w is used to compare two Unicode strings with length.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strncmp_w(utf16 a, utf16 b, int64 n);

// strcpy_a is used to copy source ACSII string to destination.
uint strcpy_a(ascii dst, ascii src);

// strcpy_w is used to copy source Unicode string to destination.
uint strcpy_w(utf16 dst, utf16 src);

// strcpy_a is used to copy source ACSII string to destination with length.
uint strncpy_a(ascii dst, ascii src, int64 n);

// strcpy_w is used to copy source Unicode string to destination with length.
uint strncpy_w(utf16 dst, utf16 src, int64 n);

#endif // LIB_STRING_H
