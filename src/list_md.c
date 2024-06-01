#include "c_types.h"
#include "lib_memory.h"
#include "list_md.h"

#pragma optimize("t", on)

void List_Init(List* list, List_Ctx* ctx, uint unit)
{
    list->ctx  = *ctx;
    list->Data = NULL;
    list->Len  = 0;
    list->Cap  = 0;
    list->Last = 0;
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
        if (i >= list->Len)
        {
            list->Last = i;
        }
        mem_copy(addr, data, list->Unit);
        list->Len++;
        return true;
    }
    panic(PANIC_UNREACHABLE_CODE);
    return false;
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
    uintptr addr = (uintptr)(list->Data);
    return (void*)(addr + index * list->Unit);
}

bool List_Find(List* list, void* data, uint equal, uint* idx)
{
    uint equLen = equal;
    if (equLen == 0)
    {
        equLen = list->Unit;
    }
    uint index = 0;
    bool found = false;
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
        found = true;
        break;
    }
    if (!found)
    {
        return false;
    }
    byte* addr = (byte*)(list->Data) + (index*list->Unit);
    mem_copy(data, addr, list->Unit);
    if (idx != NULL)
    {
        *idx = index;
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
    return list->Last * list->Unit;
}

bool List_Free(List* list)
{
    if (list->Data == NULL)
    {
        return true;
    }
    return list->ctx.free(list->Data);
}

#pragma optimize("t", off)
