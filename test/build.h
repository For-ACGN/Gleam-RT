#ifndef BUILD_H
#define BUILD_H

// RELEASE_MODE:   remove debug modules for generate shellcode
// SHELLCODE_MODE: run unit tests under runtime shellcode
// FAST_CRYPTO:    replace original algorithm to xor for test
// NOT_CAMOUFLAGE: disable all modules about camouflage for debug

// #define RELEASE_MODE
#define SHELLCODE_MODE
// #define FAST_CRYPTO
// #define NOT_CAMOUFLAGE

#ifdef SHELLCODE_MODE
    #define RELEASE_MODE
#endif // SHELLCODE_MODE

// disable special warnings for RELEASE_MODE
#ifdef RELEASE_MODE
    #pragma warning(disable: 4206)
#endif

#endif // BUILD_H
