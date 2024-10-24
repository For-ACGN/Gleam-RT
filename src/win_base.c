#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "errno.h"
#include "win_base.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    MultiByteToWideChar_t MultiByteToWideChar;
    WideCharToMultiByte_t WideCharToMultiByte;

    // submodules method
    mt_malloc_t  malloc;
    mt_calloc_t  calloc;
    mt_realloc_t realloc;
    mt_free_t    free;
} WinBase;

// methods for user
errno WB_ANSIToUTF16(ANSI s);
errno WB_UTF16ToANSI(UTF16 s);
errno WB_ANSIToUTF16N(ANSI s, uint n);
errno WB_UTF16ToANSIN(UTF16 s, uint n);

// methods for runtime
errno WB_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E1
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE1
#endif
static WinBase* getModulePointer();

static bool initModuleAPI(WinBase* module, Context* context);
static bool updateModulePointer(WinBase* module);
static bool recoverModulePointer(WinBase* module);
static bool initModuleEnvironment(WinBase* module, Context* context);
static void eraseModuleMethods(Context* context);

WinBase_M* InitWinBase(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 16384 + RandUintN(address, 128);
    uintptr methodAddr = address + 17000 + RandUintN(address, 128);
    // initialize module
    WinBase* module = (WinBase*)moduleAddr;
    mem_init(module, sizeof(WinBase));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;


}

static bool initModuleAPI(WinBase* module, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xFECF5D77CC76C334, 0x3291C4717151B366}, // MultiByteToWideChar
        { 0x32C7684AB4B518B6, 0x0C4F51C8DCCC447D}, // WideCharToMultiByte
    };
#elif _WIN32
    {
        { 0x68A627A6, 0x4087B044}, // MultiByteToWideChar
        { 0x4F572177, 0x5F4B7BE1}, // WideCharToMultiByte
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    module->MultiByteToWideChar = list[0].proc;
    module->WideCharToMultiByte = list[1].proc;
    return true;
}

