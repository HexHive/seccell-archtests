#include <stdbool.h>
#include "common.h"
#include "test.h"
#include "seccell.h"

struct cell {
  uint64_t va_start, va_end, pa;
};

struct context {
	uint64_t unused;
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
	uint64_t sepc;
	uint64_t scause;
  uint64_t stval;
  uint64_t urid;
  uint64_t uxid;
};


/******************************************
 * Cells Setup 
 *****************************************/
#define N_CELLS 4
#define M_SDS   3
static struct cell cells[N_CELLS];
static uint8_t cperms[M_SDS][N_CELLS];
static uint8_t *ptable;

void set_ptable(uint8_t *ptable_s) {
  ptable = ptable_s;
}

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
enum trap_cause {
  INVALID_CAUSE = -1,

  TRAP_TEST = 0,

  /* Traps for SCCOUNT testing */
  TRAP_SCCOUNT_BEGIN,
  TRAP_SCCOUNT_PERM_EXCEPTION = TRAP_SCCOUNT_BEGIN,
  TRAP_SCCOUNT_ADDR_EXCEPTION,
  TRAP_SCCOUNT_END,

  TRAP_SDSWITCH_BEGIN,
  TRAP_SDSWITCH_SDID = TRAP_SDSWITCH_BEGIN,
  TRAP_SDSWITCH_ADDR,
  TRAP_SDSWITCH_END,

  TRAP_SCINVAL_REVAL_BEGIN,
  TRAP_SCINVAL_REVAL_FUNC_TRAP = TRAP_SCINVAL_REVAL_BEGIN,
  TRAP_SCINVAL_REVAL_ADDR,
  TRAP_SCINVAL_REVAL_CELL_STATE,
  TRAP_SCINVAL_REVAL_END,

  TRAP_COUNT
};

static struct context ctx;
volatile static enum trap_cause trap_id;
volatile static int trap_mistakes;
volatile static uint64_t expected_stval, handler_ack;

void setup_trap_handler(void) {
  asm("csrw sscratch, %[ctx]"
      :: [ctx] "r" (&ctx));
}

#define SCCOUNT_HANDLER_ACK_SPECIAL   0xc007
#define SDSWITCH_HANDLER_ACK_SPECIAL  0xc017
#define SDINREVAL_HANDLER_ACK_SPECIAL 0xd0d0
void trap_generic_test(uint64_t handler_ack_magic, uint64_t expected_cause,
                       uint64_t expected_usid, uint64_t expected_urid) {
  handler_ack = handler_ack_magic;

  bool condition = true
                    && (ctx.scause == expected_cause)
                    && (ctx.stval == expected_stval)
                    && (get_usid() == expected_usid)
                    && (get_urid() == expected_urid);
  
  if(!condition)
    trap_mistakes += 1;
}

void trap_skip_inst(void) {
  if(ctx.sepc == SPECIAL_TRAP_ADDR) {
    /* This case is used by the raise trap mechanism
     * The return address holds the next valid inst */
    ctx.sepc = ctx.ra;
  } else {
    /* Set MXR in sstatus to enable read of the instruction */
    uint64_t sstatus;
    asm("csrr %[sstatus], sstatus;"
          : [sstatus] "=r" (sstatus)
          ::);
    asm("csrw sstatus, %[sstatus]"
          :: [sstatus] "r" (sstatus | (0x1 << 19))
          :);

    /* Different skip lengths based on compressed or not */
    uint16_t inst = *(uint16_t *)ctx.sepc;
    if((inst & 0x3) == 0x3) 
      ctx.sepc += 4;
    else
      ctx.sepc += 2;

    /* Reset MXR in sstatus */
    asm("csrw sstatus, %[sstatus]"
          :: [sstatus] "r" (sstatus)
          :);
  }
}

void c_trap_handler(void) {
  switch (trap_id)
  {
  case TRAP_TEST:
    trap_mistakes = 0xdeadbeef;
    trap_skip_inst();
    break;
  
  case TRAP_SCCOUNT_PERM_EXCEPTION:
    trap_generic_test(SCCOUNT_HANDLER_ACK_SPECIAL, 
                      RISCV_EXCP_SECCELL_ILL_PERM, 
                      0, 1);
    trap_skip_inst();
    break;

  case TRAP_SCCOUNT_ADDR_EXCEPTION:
    trap_generic_test(SCCOUNT_HANDLER_ACK_SPECIAL, 
                      RISCV_EXCP_SECCELL_ILL_ADDR, 
                      0, 1);
    trap_skip_inst();
    break;

  case TRAP_SDSWITCH_SDID:
    trap_generic_test(SDSWITCH_HANDLER_ACK_SPECIAL, 
                      RISCV_EXCP_SECCELL_INV_SDID, 
                      0, 1);
    trap_skip_inst();
    break;

  case TRAP_SDSWITCH_ADDR:
    trap_generic_test(SDSWITCH_HANDLER_ACK_SPECIAL, 
                      RISCV_EXCP_SECCELL_ILL_TGT, 
                      0, 1);
    trap_skip_inst();
    break;

  case TRAP_SCINVAL_REVAL_FUNC_TRAP:
    trap_generic_test(SDINREVAL_HANDLER_ACK_SPECIAL, 
                      RISCV_EXCP_STORE_PAGE_FAULT, 
                      0, 1);
    trap_skip_inst();
    break; 

  case TRAP_SCINVAL_REVAL_ADDR:
    trap_generic_test(SDINREVAL_HANDLER_ACK_SPECIAL,
                      RISCV_EXCP_SECCELL_ILL_ADDR,
                      0, 1);
    trap_skip_inst();
    break; 
  
  case TRAP_SCINVAL_REVAL_CELL_STATE:
    trap_generic_test(SDINREVAL_HANDLER_ACK_SPECIAL,
                      RISCV_EXCP_SECCELL_INV_CELL_STATE,
                      0, 1);
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
 * Tests for SCCount instruction
 *****************************************/
/* Testing correctness of sccount instructions for legal operands */
int sccount_test_correctness() {
  int mistakes = 0;
  trap_id = INVALID_CAUSE;

  CHECK(get_usid() == 1);
  CHECK(get_urid() == 0);
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


/* Testing exveptions for sccount with illegal permissions */
static uint8_t invalid_perms_parameters[] = {
    0x0, 0x1, 0x10, 0x20, 0x40, 0x80
  };

int sccount_exception_perms() {
  int mistakes = 0;
  trap_id = TRAP_SCCOUNT_PERM_EXCEPTION;

  for(uint8_t i = 0; i < sizeof(invalid_perms_parameters); i++) {
    trap_mistakes = 0;
    handler_ack = 0;
    uint8_t test_perm = invalid_perms_parameters[i];
    expected_stval = (((test_perm == 0)? 1: 0) << 8)
                      | test_perm;
    SCCount(cells[0].va_start, invalid_perms_parameters[i]);

    CHECK(!trap_mistakes && (handler_ack == SCCOUNT_HANDLER_ACK_SPECIAL));
  }

  return mistakes;
}

/* Testing exceptioons for sccount with invalid addresses */
static uint64_t invalid_addresses[] = {
    0x0, 0xf1f1d0d0
  };
int sccount_exception_addr() {
  int mistakes = 0;
  trap_id = TRAP_SCCOUNT_ADDR_EXCEPTION;

  for(uint8_t i = 0; i < sizeof(invalid_addresses)/sizeof(invalid_addresses[0]); i++) {
    trap_mistakes = 0;
    expected_stval = invalid_addresses[i];
    handler_ack = 0;
    SCCount(invalid_addresses[i], RT_R);

    CHECK(!trap_mistakes && (handler_ack == SCCOUNT_HANDLER_ACK_SPECIAL));
  }

  return mistakes;
}


int sccount_tests() {
  int sccount_mistakes = 0;

  sccount_mistakes += sccount_test_correctness();
  sccount_mistakes += sccount_exception_perms();
  sccount_mistakes += sccount_exception_addr();

  return sccount_mistakes;
}

/******************************************
 * Tests for SDSwitch instruction
 *****************************************/
int sdswitch_test_functionality_jals() {
  int mistakes = 0;
  trap_id = INVALID_CAUSE;
  uint64_t tgt_usid;

  /* Start at SD 1, switch to SD 2, then back to SD 1 */
  CHECK(get_usid() == 1);
  set_urid(2);
  CHECK(get_usid() == 1);
  CHECK(get_urid() == 2);
  
  tgt_usid = 2;
  jals(tgt_usid, sdswitch_test_functionality0);
  nop(5);
  entry(sdswitch_test_functionality0);
  CHECK(get_usid() == 2);
  CHECK(get_urid() == 1);

  tgt_usid = 1;
  jals(tgt_usid, sdswitch_test_functionality1);
  nop(2);
  entry(sdswitch_test_functionality1);
  CHECK(get_usid() == 1);
  CHECK(get_urid() == 2);

  return mistakes;
}

int sdswitch_test_functionality_jalrs() {
  int mistakes = 0;
  trap_id = INVALID_CAUSE;
  uint64_t tgt_usid, tgt_addr;

  /* Start at SD 1, switch to SD 2, then back to SD 1 */
  CHECK(get_usid() == 1);
  set_urid(2);
  CHECK(get_usid() == 1);
  CHECK(get_urid() == 2);
  
  tgt_usid = 2;
  tgt_addr = (uint64_t)&&sdswitch_test_functionality0;
  jalrs(tgt_usid, tgt_addr);
  nop(5);
sdswitch_test_functionality0:
  entry(_sdswitch_test_functionality0);
  CHECK(get_usid() == 2);
  CHECK(get_urid() == 1);

  tgt_usid = 1;
  tgt_addr = (uint64_t)&&sdswitch_test_functionality1;
  jalrs(tgt_usid, tgt_addr);
  nop(2);
sdswitch_test_functionality1:
  entry(_sdswitch_test_functionality1);
  CHECK(get_usid() == 1);
  CHECK(get_urid() == 2);

  return mistakes;
}

int sdswitch_exception_sdid() {
  int mistakes = 0;
  trap_id = TRAP_SDSWITCH_SDID;
  uint64_t tgt_usid, tgt_addr;

  /* Try to switch to secdiv 0, and check fault */
  CHECK(get_usid() == 1);
  tgt_usid = 0;
  expected_stval = 0;
  handler_ack = 0;
  trap_mistakes = 0;
  jals(tgt_usid, sdswitch_test_exception_sdid0);
  nop(5);
  entry(sdswitch_test_exception_sdid0);
  CHECK(!trap_mistakes && (handler_ack == SDSWITCH_HANDLER_ACK_SPECIAL));

  /* Try to switch to secdiv 1024, and check fault */
  CHECK(get_usid() == 1);
  tgt_usid = 1024;
  expected_stval = 1024;
  handler_ack = 0;
  trap_mistakes = 0;
  jals(tgt_usid, sdswitch_test_exception_sdid1);
  nop(3);
  entry(sdswitch_test_exception_sdid1);
  CHECK(!trap_mistakes && (handler_ack == SDSWITCH_HANDLER_ACK_SPECIAL));

  /* Try to switch to secdiv 1024 with jalrs, and check fault */
  CHECK(get_usid() == 1);
  tgt_usid = 1024;
  expected_stval = 1024;
  tgt_addr = (uint64_t)&&sdswitch_test_exception_sdid2;
  handler_ack = 0;
  trap_mistakes = 0;
  jalrs(tgt_usid, tgt_addr);
  nop(7);
sdswitch_test_exception_sdid2:
  entry(_sdswitch_test_exception_sdid2);
  CHECK(!trap_mistakes && (handler_ack == SDSWITCH_HANDLER_ACK_SPECIAL));

  return mistakes;
}

int sdswitch_exception_addr(void) {
  int mistakes = 0;
  trap_id = TRAP_SDSWITCH_ADDR;
  uint64_t tgt_usid, tgt_addr;

  /* Try to switch to instruction before entry and check fault */
  CHECK(get_usid() == 1);
  tgt_usid = 2;
  expected_stval = (uint64_t)&&sdswitch_test_exception_addr0;
  handler_ack = 0;
  trap_mistakes = 0;
  jals(tgt_usid, _sdswitch_test_exception_addr0);
  nop(5);
sdswitch_test_exception_addr0:
  asm("_sdswitch_test_exception_addr0:");
  CHECK(!trap_mistakes && (handler_ack == SDSWITCH_HANDLER_ACK_SPECIAL));

  /* Try to switch to instruction before entry with jalrs and check fault */
  CHECK(get_usid() == 1);
  tgt_usid = 1024;
  tgt_addr = (uint64_t)&&sdswitch_test_exception_addr1 - 2;
  expected_stval = tgt_addr;
  handler_ack = 0;
  trap_mistakes = 0;
  jalrs(tgt_usid, tgt_addr);
  nop(7);
sdswitch_test_exception_addr1:
  entry(_sdswitch_test_exception_addr1);
  CHECK(!trap_mistakes && (handler_ack == SDSWITCH_HANDLER_ACK_SPECIAL));

  return mistakes;
}

int sdswitch_tests() {
  int sdswitch_mistakes = 0;

  sdswitch_mistakes += sdswitch_test_functionality_jals();
  sdswitch_mistakes += sdswitch_test_functionality_jalrs();
  sdswitch_mistakes += sdswitch_exception_sdid();
  sdswitch_mistakes += sdswitch_exception_addr();

  return sdswitch_mistakes;
}

/******************************************
 * Tests for SCInval/Reval instruction
 *****************************************/
int scinval_reval_functionality(void) {
  int mistakes = 0;

  /* We will repeatedly invalidate and revalidate the 
   * cell 4, which aliases to ptable:
   * RW -> inval -> reval R -> inval -> reval RW */
  volatile uint8_t *perms_ptr = ptable + (16 * 64) + (64 * 1) + 4;
  volatile uint8_t *sup_perms_ptr = ptable + (16 * 64) + (64 * 0) + 4;
  volatile uint128_t *desc_ptr = (volatile uint128_t *)(ptable + 0x40);
  volatile uint8_t *ptr_under_test = (uint8_t *)cells[3].va_start;
  volatile uint8_t junk = 0;

  CHECK(get_usid() == 1);
  CHECK(is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc7);
  CHECK(*sup_perms_ptr == 0xcf);
  /* This ptr is still valid, and this dereference should not fault.
   * This byte is currently reserved by SecCells, and should be zero */
  trap_id = INVALID_CAUSE;
  CHECK(*ptr_under_test == 0);

  inval(ptr_under_test);
  CHECK(get_usid() == 1);
  CHECK(!is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc0);
  CHECK(*sup_perms_ptr == 0xce);
  /* This ptr access is now invalid, and this dereference should fault. */
  trap_id = TRAP_SCINVAL_REVAL_FUNC_TRAP;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t)ptr_under_test;
  *ptr_under_test = 0;
  CHECK(!trap_mistakes && (handler_ack == SDINREVAL_HANDLER_ACK_SPECIAL));

  reval(ptr_under_test, RT_R);
  CHECK(get_usid() == 1);
  CHECK(is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc3);
  CHECK(*sup_perms_ptr == 0xcf);
  /* This ptr is again valid, and this dereference should not fault.
   * This byte is currently reserved by SecCells, and should be zero */
  trap_id = INVALID_CAUSE;
  CHECK(*ptr_under_test == 0);


  inval(ptr_under_test);
  CHECK(get_usid() == 1);
  CHECK(!is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc0);
  CHECK(*sup_perms_ptr == 0xce);
  /* This ptr access is now invalid, and this dereference should fault. */
  trap_id = TRAP_SCINVAL_REVAL_FUNC_TRAP;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t)ptr_under_test;
  *ptr_under_test = 0;
  CHECK(!trap_mistakes && (handler_ack == SDINREVAL_HANDLER_ACK_SPECIAL));

  reval(ptr_under_test, RT_R | RT_W);
  CHECK(get_usid() == 1);
  CHECK(is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc7);
  CHECK(*sup_perms_ptr == 0xcf);
  /* This ptr is again valid, and this dereference should not fault.
   * This byte is currently reserved by SecCells, and should be zero */
  trap_id = INVALID_CAUSE;
  CHECK(*ptr_under_test == 0);

  return mistakes;
}

int scinval_reval_exception_addr(void) {
  int mistakes = 0;

  uint8_t *faulty_addr = (uint8_t *)0xfeaf1eaf;

  trap_id = TRAP_SCINVAL_REVAL_ADDR;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t) faulty_addr;
  inval(faulty_addr);
  CHECK(!trap_mistakes && (handler_ack == SDINREVAL_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCINVAL_REVAL_ADDR;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t) faulty_addr;
  reval(faulty_addr, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SDINREVAL_HANDLER_ACK_SPECIAL));

  return mistakes;
}

int scinval_reval_exception_celldesc(void) {
  int mistakes = 0;

  uint8_t *valid_addr = (uint8_t *)cells[3].va_start;
  uint8_t *shared_addr = (uint8_t *)cells[2].va_start;

  trap_id = TRAP_SCINVAL_REVAL_CELL_STATE;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t) 0; /* Since cell is already valid */
  reval(valid_addr, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SDINREVAL_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCINVAL_REVAL_CELL_STATE;
  handler_ack = 0;
  trap_mistakes = 0;
  inval(valid_addr);
  expected_stval = (uint64_t) 0; /* Since cell is already invalid */
  inval(valid_addr);
  CHECK(!trap_mistakes && (handler_ack == SDINREVAL_HANDLER_ACK_SPECIAL));
  reval(valid_addr, RT_R | RT_W);

  trap_id = TRAP_SCINVAL_REVAL_CELL_STATE;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t) 1; /* Since cell is shared with other SD */
  inval(shared_addr);
  CHECK(!trap_mistakes && (handler_ack == SDINREVAL_HANDLER_ACK_SPECIAL));

  return mistakes;
}

int scinval_reval_tests(void) {
  int scinval_reval_mistakes = 0;

  scinval_reval_mistakes += scinval_reval_functionality();
  scinval_reval_mistakes += scinval_reval_exception_addr();
  scinval_reval_mistakes += scinval_reval_exception_celldesc();

  return scinval_reval_mistakes;
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
  mistakes += sdswitch_tests();
  mistakes += scinval_reval_tests();

  if(mistakes)
    wrong();
  else
    correct();
}
