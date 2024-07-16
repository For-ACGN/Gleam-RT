#ifndef ARGUMENT_H
#define ARGUMENT_H

// +----------+----------+----------+----------+----------+
// |    key   |   size   | num args | arg size | arg data |
// +----------+----------+----------+----------+----------+
// | 32 bytes |  uint32  |  uint32  |  uint32  |    var   |
// +----------+----------+----------+----------+----------+

#define ARG_OFFSET_CRYPTO_KEY (0+0)
#define ARG_OFFSET_TOTAL_SIZE (0+32)
#define ARG_OFFSET_NUM_ARGS   (32+4)
#define ARG_OFFSET_FIRST_ARG  (36+4)

// reserve stub for store arguments
extern void Args_Stub();

#endif // ARGUMENT_H
