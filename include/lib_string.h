#ifndef LIB_STRING_H
#define LIB_STRING_H

#include "c_types.h"

typedef byte*   ascii;
typedef uint16* utf16;

// strlen_a is used to calculate ACSII string length.
uint strlen_a(ascii s);

// strlen_w is used to calculate Unicode string length.
uint strlen_w(utf16 s);

#endif // LIB_STRING_H
