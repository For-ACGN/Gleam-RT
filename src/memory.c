#include "go_types.h"
#include "hash_api.h"
#include "windows_t.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"

typedef struct {
    // API address
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;

    uint pages;
} MemMgr;

static bool initAPI(MemMgr* manager, FindAPI_t findAPI);

uint InitMemMgr(FindAPI_t findAPI)
{
    // allocate memory for store MemMgr structure.
    #ifdef _WIN64
    uint64 hash = 0xB6A1D0D4A275D4B6;
    uint64 key  = 0x64CB4D66EC0BEFD9;
    #elif _WIN32
    uint32 hash = 0xC3DE112E;
    uint32 key  = 0x8D9EA74F;
    #endif
    VirtualAlloc virtualAlloc = (VirtualAlloc)findAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    uintptr address = virtualAlloc(0, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (address == NULL)
    {
        return NULL;
    }

    byte encData1[] = {
        0, 1, 2, 3, 0, 1, 2, 3,0, 1, 2, 3,0, 1, 2, 3,
        0, 1, 2, 3, 0, 1, 2, 3,0, 1, 2, 3,0, 1, 2, 3,
    };

    byte encData2[] = {
        1, 1, 2, 3, 0, 1, 2, 3,0, 1, 2, 3,0, 1, 2, 3,
        0, 1, 2, 3, 0, 1, 2, 3,0, 1, 2, 3,0, 1, 2, 3,
    };

    byte encKey[] = { 
        0, 1, 1, 13, 0, 12, 2, 64, 0, 200, 2, 3, 123, 1, 44, 3,
        0, 1, 2, 13, 200, 31, 2, 21, 0, 1, 48, 3, 48, 1, 1, 3,
    };

    // RandBuf(&encKey[0], 32);

    EncryptBuf(&encData1[0], 32, &encKey[0]);
    EncryptBuf(&encData2[0], 32, &encKey[0]);

    DecryptBuf(&encData1[0], 32, &encKey[0]);
    DecryptBuf(&encData2[0], 32, &encKey[0]);


    return encData1[0] + encData2[0];
}

static bool initAPI(MemMgr* manager, FindAPI_t findAPI)
{
#ifdef _WIN64
    uint64 hash = 0xB82F958E3932DE49;
    uint64 key  = 0x1CA95AA0C4E69F35;
#elif _WIN32
    uint32 hash = 0xFE192059;
    uint32 key  = 0x397FD02C;
#endif
    VirtualFree virtualFree = (VirtualFree)findAPI(hash, key);
    if (virtualFree == NULL)
    {
        return false;
    }
#ifdef _WIN64
    hash = 0x8CDC3CBC1ABF3F5F;
    key  = 0xC3AEEDC9843D7B34;
#elif _WIN32
    hash = 0xD41DCE2B;
    key  = 0xEB37C512;
#endif
    VirtualProtect virtualProtect = (VirtualProtect)findAPI(hash, key);
    if (virtualProtect == NULL)
    {
        return false;
    }


    return true;
}

static void* Alloc(uint size)
{

}

static void Free(uintptr address)
{

}
