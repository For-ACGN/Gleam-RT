#include "go_types.h"
#include "list_md.h"

void InitList(List* list, List_Ctx* ctx, uint unit)
{
    list->ctx  = *ctx;
    list->Len  = 0;
    list->Cap  = 0;
    list->Unit = unit;
}

bool List_Insert(List* list, void* data)
{
    if (list->Len >= list->Cap)
    {
        bool success;
        if (list->Cap == 0)
        {
            success = List_Resize(list, 4);
        } else {
            success = List_Resize(list, list->Cap * 2);
        }
        if (!success)
        {
            return false;
        }
    }



    return true;
}

bool List_Delete(List* list, uint index)
{
    return true;
}

bool List_Resize(List* list, uint cap)
{
    return true;
}

bool List_Free(List* list)
{
    return true;
}
