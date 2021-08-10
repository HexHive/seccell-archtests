#include "common.h"
#include "test.h"
#include "seccell.h"

#define N_CELLS 3
#define M_SDS   3
struct cell cells[N_CELLS];
uint8_t cperms[M_SDS][N_CELLS];

#define CHECK(x) \
  if (!(x)) {    \
    mistakes++;  \
  }

/******************************************
 * Wrappers for SecCell instructions
 *****************************************/
uint64_t SCCount(uint64_t addr, uint8_t perm) {
  uint64_t ret;
  count(ret, addr, perm);
  return ret;
}

/******************************************
 * Tests for SCcount instruction
 *****************************************/
int sccount_tests() {
  int mistakes = 0;

  for(int cidx = 0; cidx < N_CELLS; cidx++) {
    int rcount = 0, wcount = 0, xcount = 0;

    for(int sdidx = 0; sdidx < M_SDS; sdidx++){
      if(cperms[sdidx][cidx] & RT_R == RT_R) rcount++;
      if(cperms[sdidx][cidx] & RT_W == RT_W) wcount++;
      if(cperms[sdidx][cidx] & RT_X == RT_X) xcount++;
    }

    CHECK(SCCount(cells[cidx].va_start, RT_R) == rcount);
    CHECK(SCCount(cells[cidx].va_start, RT_W) == wcount);
    CHECK(SCCount(cells[cidx].va_start, RT_X) == xcount);
  }

  return mistakes;
}












void correct() {
  while(1);
}

void wrong() {
  while(1);
}

void test(void) {
  int mistakes = 0;

  mistakes += sccount_tests();

}
