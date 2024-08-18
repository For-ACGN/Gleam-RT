#ifndef LIST_MD_H
#define LIST_MD_H

#include "c_types.h"
#include "lib_memory.h"

typedef struct {
    malloc_t  malloc;
    realloc_t realloc;
    free_t    free;
} List_Ctx;

typedef struct {
    List_Ctx ctx;

    void* Data;
    uint  Len;
    uint  Cap;
    uint  Last;
    uint  Unit;
} List;

// If an Insert or Delete operation is performed  
// while traversing the List, the historical status 
// must be recorded before traversing.

// List_Init is used to initialize a mesh dynamic list.
void List_Init(List* list, List_Ctx* ctx, uint unit);

// List_Set is used to set element by index.
// If index > cap, it will resize automatically.
bool List_Set(List* list, uint index, void* data);

// List_Get is used to get element by index.
// If index > cap, it will return NULL.
void* List_Get(List* list, uint index);

// List_Insert is used to insert a element to list.
bool List_Insert(List* list, void* data);

// List_Delete is used to delete element by index.
bool List_Delete(List* list, uint index);

// List_Find is used to find data and return index.
// Equal is used compare a part of data, if equal is zero,
// it will compare whole data.
// If index is NULL, it will not return the element index.
bool List_Find(List* list, void* data, uint equal, uint* index);

// List_Resize is used to resize list buffer size.
// It will change capacity, it can be smaller than old.
bool List_Resize(List* list, uint cap);

// List_Size is used to calculate the buffer usage.
uint List_Size(List* list);

// List_Free is used to free list buffer.
bool List_Free(List* list);

#endif // LIST_MD_H
