#include "go_types.h"
#include "hash_api.h"
#include "memory.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain()
{
    return InitMemMgr(&FindAPI);
}
