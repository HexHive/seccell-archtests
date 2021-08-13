#include "common.h"
#include "test.h"
#include "seccell.h"

struct cell {
  uint64_t va_start, va_end, pa;
};

struct context {
	uint64_t epc;
	uint64_t ra;
	uint64_t sp;
	uint64_t gp;
	uint64_t tp;
	uint64_t t0;
	uint64_t t1;
	uint64_t t2;
	uint64_t s0;
	uint64_t s1;
	uint64_t a0;
	uint64_t a1;
	uint64_t a2;
	uint64_t a3;
	uint64_t a4;
	uint64_t a5;
	uint64_t a6;
	uint64_t a7;
	uint64_t s2;
	uint64_t s3;
	uint64_t s4;
	uint64_t s5;
	uint64_t s6;
	uint64_t s7;
	uint64_t s8;
	uint64_t s9;
	uint64_t s10;
	uint64_t s11;
	uint64_t t3;
	uint64_t t4;
	uint64_t t5;
	uint64_t t6;
	/* Supervisor/Machine CSRs */
	uint64_t status;
	uint64_t badaddr;
	uint64_t cause;
  uint64_t urid;
  uint64_t uxid;
};

enum trap_cause {
  INVALID_CAUSE = -1,

  TRAP_TEST = 0,

  TRAP_COUNT
};

/******************************************
 * Cells Setup 
 *****************************************/
#define N_CELLS 3
#define M_SDS   3
static struct cell cells[N_CELLS];
static uint8_t cperms[M_SDS][N_CELLS];

void set_cell(int cidx, uint64_t va_start, uint64_t va_end, uint64_t pa) {
  cells[cidx].va_start = va_start;
  cells[cidx].va_end = va_end;
  cells[cidx].pa = pa;
}

void set_cell_perm(int sdidx, int cidx, uint8_t perm) {
  cperms[sdidx][cidx] = perm;
}

#define CHECK(x) \
  if (!(x)) {    \
    mistakes++;  \
  }

/******************************************
 * Handling traps during tests
 * These functions run as supervisor
 *****************************************/
static struct context ctx;
static enum trap_cause trap_id;
static int trap_mistakes;

void setup_trap_handler(void) {
  asm("csrw sscratch, %[ctx]"
      :: [ctx] "r" (&ctx));
}

void trap_skip_inst(void) {
  if(ctx.badaddr == SPECIAL_TRAP_ADDR) {
    // This case is used by the raise trap mechanism
    // The return address holds the next valid inst
    ctx.badaddr = ctx.ra;
  } else {
    //TODO: Determine compressed or not
    ctx.badaddr += 2;
  }
}

void c_trap_handler(void) {
  switch (trap_id)
  {
  case TRAP_TEST:
    trap_mistakes = 0xdeadbeef;
    trap_skip_inst();
    break;
  
  /* Unknown/invalid causes will lead to another fault */
  case INVALID_CAUSE:
  default:
    raise_trap();
  }
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

    for(int sdidx = 1; sdidx < M_SDS; sdidx++){
      if((cperms[sdidx][cidx] & RT_R) == RT_R) rcount++;
      if((cperms[sdidx][cidx] & RT_W) == RT_W) wcount++;
      if((cperms[sdidx][cidx] & RT_X) == RT_X) xcount++;
    }

    CHECK(SCCount(cells[cidx].va_start, RT_R) == rcount);
    CHECK(SCCount(cells[cidx].va_start, RT_W) == wcount);
    CHECK(SCCount(cells[cidx].va_start, RT_X) == xcount);
  }

  return mistakes;
}











/******************************************
 * Tests Suite
 *****************************************/
void correct() {
  while(1);
}

void wrong() {
  while(1);
}

void test(void) {
  int mistakes = 0;

  /* Verify the testing mechanism */
  trap_id = TRAP_TEST;
  raise_trap();
  CHECK(trap_mistakes == 0xdeadbeef);

  /* Begin actual testing */
  mistakes += sccount_tests();

  if(mistakes)
    wrong();
  else
    correct();
}
