#include "go_types.h"
#include "memory.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain()
{
    return InitMemMgr(NULL);
}
