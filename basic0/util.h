#include <inttypes.h>

#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"
void memset(uint8_t *addr, uint8_t c, int n);

#define CLINES                      64
#define PT(ptable, T, sd, ci) 	    (ptable + (16 * T * CLINES) + (sd * T * CLINES) + ci)
#define GT(ptable, R, T, sd, ci)    ((uint32_t *)(ptable + (16 * T * CLINES) + (R * T * CLINES) + (sd * 4 * T * CLINES) + (4 * ci)))

#define G(sdtgt, perm)              ((sdtgt << 3) | perm)
#define SDINV                       (-1)
