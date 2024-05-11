#include "c_types.h"
#include "lib_mem.h"
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
        mem_copy(addr, data, list->Unit);
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
    mem_clean(addr, list->Unit);
    list->Len--;
    return true;
}

void* List_Get(List* list, uint index)
{
    if (index + 1 > list->Cap)
    {
        return NULL;
    }
    return (void*)((uintptr)(list->Data) + index * list->Unit);
}

bool List_Find(List* list, void* data, uint equal, uint* idx)
{
    uint equLen = equal;
    if (equLen == 0)
    {
        equLen = list->Unit;
    }
    uint target = 0;
    uint index  = 0;
    for (uint num = 0; num < list->Len; index++)
    {
        void* item = List_Get(list, index);
        if (mem_zero(item, equLen))
        {
            continue;
        }
        if (!mem_equal(item, data, equLen))
        {
            num++;
            continue;
        }
        target = index;
        break;
    }
    if (target == 0)
    {
        return false;
    }
    byte* addr = (byte*)(list->Data) + (target*list->Unit);
    mem_copy(data, addr, list->Unit);
    if (idx != NULL)
    {
        *idx = target;
    }
    return true;
}

bool List_Resize(List* list, uint cap)
{
    uint  size = cap * list->Unit;
    void* data;
    if (list->Data != NULL)
    {
        data = list->ctx.realloc(list->Data, size);
    } else {
        data = list->ctx.malloc(size);
    }
    if (data == NULL)
    {
        return false;
    }
    list->Data = data;
    list->Cap  = cap;
    return true;
}

uint List_Size(List* list)
{
    return list->Cap * list->Unit;
}

bool List_Free(List* list)
{
    return list->ctx.free(list->Data);
}
