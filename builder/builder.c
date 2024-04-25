#include "go_types.h"
#include "hash_api.h"
#include "runtime.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain()
{
    RuntimeM* runtime = NewRuntime(&FindAPI);
    if (runtime == NULL)
    {
        return -1;
    }
    runtime->Hide();
    return 0;
}
