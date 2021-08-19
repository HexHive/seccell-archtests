#include <inttypes.h>

/* Special trap address has to be aligned to 4 (or 2 for compressed) */
#define SPECIAL_TRAP_ADDR 0xdeafbeec
#define raise_trap()                                        \
  do {                                                      \
    void (*trap)(void) = (void (*)(void))SPECIAL_TRAP_ADDR; \
    trap();                                                 \
  } while(0)


typedef unsigned __int128 uint128_t;
