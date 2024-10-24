#ifndef WIN_BASE_H
#define WIN_BASE_H

#include "c_types.h"
#include "windows_t.h"
#include "lib_string.h"
#include "context.h"
#include "errno.h"

// The buffer allocated from methods must call Runtime_M.Memory.Free().

typedef UTF16 (*WBANSIToUTF16_t)(ANSI s);
typedef ANSI  (*WBUTF16ToANSI_t)(UTF16 s);
typedef UTF16 (*WBANSIToUTF16N_t)(ANSI s, uint n);
typedef ANSI  (*WBUTF16ToANSIN_t)(UTF16 s, uint n);

typedef errno (*WBUninstall_t)();

typedef struct {
    WBANSIToUTF16_t  ANSIToUTF16;
    WBUTF16ToANSI_t  UTF16ToANSI;
    WBANSIToUTF16N_t ANSIToUTF16N;
    WBUTF16ToANSIN_t UTF16ToANSIN;

    WBUninstall_t Uninstall;
} WinBase_M;

WinBase_M* InitWinBase(Context* context);

#endif // WIN_BASE_H
