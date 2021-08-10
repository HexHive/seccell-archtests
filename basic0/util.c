#include "util.h"

#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"
void memset(uint8_t *addr, uint8_t c, int n) {
  while(n-- > 0) 
    *addr++ = c;
}