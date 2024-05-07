#include "go_types.h"
#include "list_md.h"

void List_Init(List* list, List_Ctx* ctx, uint unit)
{
    list->ctx  = *ctx;
    list->Data = NULL;
    list->Len  = 0;
    list->Cap  = 0;
    list->Unit = unit;
}

bool List_Insert(List* list, void* data)
{
    bool resized = false;
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
        resized = true;
    }
    // set the begin position
    uint i = 0;
    if (resized)
    {
        i = list->Len;
    }
    // search empty for insert item.
    byte* addr;
    for (; i < list->Cap; i++)
    {
        addr = ((byte*)(list->Data) + i * list->Unit);
        bool empty = true;
        for (uint j = 0; j < list->Unit; j++)
        {
            if (*(addr + j) == NULL)
            {
                continue;
            }
            empty = false;
            break;
        }
        if (!empty)
        {
            continue;
        }
        copy(addr, data, list->Unit);
        break;
    }
    list->Len++;
    return true;
}

bool List_Delete(List* list, uint index)
{
    if (index + 1 > list->Cap)
    {
        return false;
    }
    byte* addr = (byte*)(list->Data) + index * list->Unit;
    memset(addr, 0, list->Unit);
    list->Len--;
    return true;
}

bool List_Resize(List* list, uint cap)
{
    void* data;
    if (list->Data != NULL)
    {
        data = list->ctx.realloc(list->Data, cap * list->Unit);
    } else {
        data = list->ctx.malloc(cap * list->Unit);
    }
    if (data == NULL)
    {
        return false;
    }
    list->Data = data;
    list->Cap  = cap;
    return true;
}

bool List_Free(List* list)
{
    return list->ctx.free(list->Data);
}
