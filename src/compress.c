#include "c_types.h"
#include "compress.h"

/* internal data structure */
struct APDSTATE {
    uint8* src;
    uint8* dst;
    uint   nbit;
    uint   tag;
};

static uint aP_getbit(struct APDSTATE* ud)
{
    uint bit;

    /* check if tag is empty */
    if (!ud->nbit--)
    {
        /* load next tag */
        ud->tag = *ud->src++;
        ud->nbit = 7;
    }

    /* shift bit out of tag */
    bit = (ud->tag >> 7) & 0x01;
    ud->tag <<= 1;

    return bit;
}

static uint aP_getgamma(struct APDSTATE* ud)
{
    uint result = 1;

    /* input gamma2-encoded bits */
    do
    {
        result = (result << 1) + aP_getbit(ud);
    } while (aP_getbit(ud));

    return result;
}

uint Compress(void* dst, void* src)
{
    return 0;
}

uint Decompress(void* dst, void* src)
{
    struct APDSTATE ud = {
        .src  = (uint8*)src,
        .dst  = (uint8*)dst,
        .tag  = 0,
        .nbit = 0,
    };
    uint offs, len, R0, LWM;
    int  done;
    int  i;

    R0 = (uint)-1;
    LWM = 0;
    done = 0;

    /* first byte verbatim */
    *ud.dst++ = *ud.src++;

    /* main decompression loop */
    while (!done)
    {
        if (aP_getbit(&ud))
        {
            if (aP_getbit(&ud))
            {
                if (aP_getbit(&ud))
                {
                    offs = 0;

                    for (i = 4; i; i--)
                    {
                        offs = (offs << 1) + aP_getbit(&ud);
                    }

                    if (offs)
                    {
                        *ud.dst = *(ud.dst - offs);
                        ud.dst++;
                    } else
                    {
                        *ud.dst++ = 0x00;
                    }

                    LWM = 0;
                } else
                {
                    offs = *ud.src++;

                    len = 2 + (offs & 0x0001);

                    offs >>= 1;

                    if (offs)
                    {
                        for (; len; len--)
                        {
                            *ud.dst = *(ud.dst - offs);
                            ud.dst++;
                        }
                    } else
                    {
                        done = 1;
                    }

                    R0 = offs;
                    LWM = 1;
                }
            } else
            {
                offs = aP_getgamma(&ud);

                if ((LWM == 0) && (offs == 2))
                {
                    offs = R0;

                    len = aP_getgamma(&ud);

                    for (; len; len--)
                    {
                        *ud.dst = *(ud.dst - offs);
                        ud.dst++;
                    }
                } else
                {
                    if (LWM == 0)
                    {
                        offs -= 3;
                    } else
                    {
                        offs -= 2;
                    }

                    offs <<= 8;
                    offs += *ud.src++;

                    len = aP_getgamma(&ud);

                    if (offs >= 32000)
                    {
                        len++;
                    }
                    if (offs >= 1280)
                    {
                        len++;
                    }
                    if (offs < 128)
                    {
                        len += 2;
                    }

                    for (; len; len--)
                    {
                        *ud.dst = *(ud.dst - offs);
                        ud.dst++;
                    }

                    R0 = offs;
                }

                LWM = 1;
            }
        } else
        {
            *ud.dst++ = *ud.src++;
            LWM = 0;
        }
    }

    return (uint)(ud.dst - (uint8*)dst);
}
