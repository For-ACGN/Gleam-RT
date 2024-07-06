#include "epilogue.h"

// prevent it be linked to other empty funtions.
#pragma optimize("", off)
void Epilogue()
{
    char var = 0xFA;
    return;
}
#pragma optimize("", on)
