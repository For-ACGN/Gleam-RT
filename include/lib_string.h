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

#endif // LIB_STRING_H
