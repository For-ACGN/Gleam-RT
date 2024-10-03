#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "win_file.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    CreateFileA_t   CreateFileA;
    CreateFileW_t   CreateFileW;
    GetFileSizeEx_t GetFileSizeEx;
    ReadFile_t      ReadFile;
    WriteFile_t     WriteFile;
    CloseHandle_t   CloseHandle;

    // runtime methods
    malloc_t malloc;
} WinFile;

// methods for user
bool WF_ReadFileA(LPSTR path, byte** buf, uint* size);
bool WF_ReadFileW(LPWSTR path, byte** buf, uint* size);
bool WF_WriteFileA(LPSTR path, byte* buf, uint size);
bool WF_WriteFileW(LPWSTR path, byte* buf, uint size);

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111A1
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDA1
#endif
static WinFile* getModulePointer();

static bool initModuleAPI(WinFile* module, Context* context);
static bool updateModulePointer(WinFile* module);
static bool recoverModulePointer(WinFile* module);
static bool initModuleEnvironment(WinFile* module, Context* context);

static void eraseModuleMethods(Context* context);

WinFile_M* InitWinFile(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 4096 + RandUintN(address, 128);
    uintptr methodAddr = address + 4600 + RandUintN(address, 128);
    // initialize module
    WinFile* module = (WinFile*)moduleAddr;
    mem_init(module, sizeof(WinFile));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_FILE_INIT_API;
            break;
        }
        if (!updateModulePointer(module))
        {
            errno = ERR_WIN_FILE_UPDATE_PTR;
            break;
        }
        if (!initModuleEnvironment(module, context))
        {
            errno = ERR_WIN_FILE_INIT_ENV;
            break;
        }
        break;
    }
    eraseModuleMethods(context);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    // create methods
    WinFile_M* method = (WinFile_M*)methodAddr;
    method->ReadFileA  = GetFuncAddr(&WF_ReadFileA);
    method->ReadFileW  = GetFuncAddr(&WF_ReadFileW);
    method->WriteFileA = GetFuncAddr(&WF_WriteFileA);
    method->WriteFileW = GetFuncAddr(&WF_WriteFileW);
    return method;
}

static bool initModuleAPI(WinFile* module, Context* context)
{
    return true;
}

static bool updateModulePointer(WinFile* module)
{
    return true;
}

static bool recoverModulePointer(WinFile* module)
{
    return true;
}

static bool initModuleEnvironment(WinFile* module, Context* context)
{
    return true;
}


static void eraseModuleMethods(Context* context)
{

}

// updateModulePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateModulePointer will fail.
#pragma optimize("", off)
static WinFile* getModulePointer()
{
    uintptr pointer = MODULE_POINTER;
    return (WinFile*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
bool WF_ReadFileA(LPSTR path, byte** buf, uint* size)
{
    return true;
}

__declspec(noinline)
bool WF_ReadFileW(LPWSTR path, byte** buf, uint* size)
{
    return true;
}

__declspec(noinline)
bool WF_WriteFileA(LPSTR path, byte* buf, uint size)
{
    return true;
}

__declspec(noinline)
bool WF_WriteFileW(LPWSTR path, byte* buf, uint size)
{
    return true;
}
