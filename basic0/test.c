#include <stdbool.h>
#include "common.h"
#include "test.h"
#include "seccell.h"
#include "util.h"

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
typedef struct {
  uint32_t M, N, R, T;
} meta_t;
static struct cell cells[N_CELLS];
static uint8_t cperms[M_SDS][N_CELLS];
static uint8_t *ptable;
static meta_t meta;

void set_ptable(uint8_t *ptable_s, uint32_t M, uint32_t N, uint32_t R, uint32_t T) {
  ptable = ptable_s;
  meta.N = N;
  meta.M = M;
  meta.T = T;
  meta.R = R;
}

void set_cell(int cidx, uint64_t va_start, uint64_t va_end, uint64_t pa) {
  cells[cidx].va_start = va_start;
  cells[cidx].va_end = va_end;
  cells[cidx].pa = pa;
}

void set_cell_perm(int sdidx, int cidx, uint8_t perm) {
  cperms[sdidx][cidx] = perm;
}

void wrong();

#define CHECK(x) \
  if (!(x)) {    \
    wrong();     \
  }

/******************************************
 * Handling traps during tests
 * These functions run as supervisor
 *****************************************/
enum trap_cause {
  INVALID_CAUSE = -1,

  TRAP_TEST = 0,

  /* Traps for SCExcl testing */
  TRAP_SCEXCL_BEGIN,
  TRAP_SCEXCL_PERM_EXCEPTION = TRAP_SCEXCL_BEGIN,
  TRAP_SCEXCL_ADDR_EXCEPTION,
  TRAP_SCEXCL_CELL_STATE,
  TRAP_SCEXCL_END,

  TRAP_SDSWITCH_BEGIN,
  TRAP_SDSWITCH_SDID = TRAP_SDSWITCH_BEGIN,
  TRAP_SDSWITCH_ADDR,
  TRAP_SDSWITCH_END,

  TRAP_SCINVAL_REVAL_BEGIN,
  TRAP_SCINVAL_REVAL_FUNC_TRAP = TRAP_SCINVAL_REVAL_BEGIN,
  TRAP_SCINVAL_REVAL_ADDR,
  TRAP_SCINVAL_REVAL_CELL_STATE,
  TRAP_SCINVAL_REVAL_PERMS,
  TRAP_SCINVAL_REVAL_END,

  TRAP_SCPROT_BEGIN,
  TRAP_SCPROT_ADDR = TRAP_SCPROT_BEGIN,
  TRAP_SCPROT_PERM,
  TRAP_SCPROT_INVCELL,
  TRAP_SCPROT_END,

  TRAP_SCGRANT_BEGIN,
  TRAP_SCGRANT_ADDR = TRAP_SCGRANT_BEGIN,
  TRAP_SCGRANT_PERM,
  TRAP_SCGRANT_SDID,
  TRAP_SCGRANT_INVCELL,
  TRAP_SCGRANT_END,

  TRAP_SCTFER_BEGIN,
  TRAP_SCTFER_ADDR = TRAP_SCTFER_BEGIN,
  TRAP_SCTFER_PERM,
  TRAP_SCTFER_SDID,
  TRAP_SCTFER_INVCELL,
  TRAP_SCTFER_END,

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

#define SCEXCL_HANDLER_ACK_SPECIAL   0xc007
#define SDSWITCH_HANDLER_ACK_SPECIAL  0xc017
#define SCINREVAL_HANDLER_ACK_SPECIAL 0xd0d0
#define SCPROT_HANDLER_ACK_SPECIAL    0xf0d0
#define SCGRANT_HANDLER_ACK_SPECIAL   0xd1ed
#define SCTFER_HANDLER_ACK_SPECIAL    0xf1f0

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
  uint64_t ack_magic, exp_type;

  if(trap_id == TRAP_TEST) {
    trap_mistakes = 0xdeadbeef;
    trap_skip_inst();
    return;
  }

  if((trap_id >= TRAP_SCEXCL_BEGIN) && (trap_id < TRAP_SCEXCL_END))
    ack_magic = SCEXCL_HANDLER_ACK_SPECIAL;
  else if((trap_id >= TRAP_SDSWITCH_BEGIN) && (trap_id < TRAP_SDSWITCH_END))
    ack_magic = SDSWITCH_HANDLER_ACK_SPECIAL;
  else if((trap_id >= TRAP_SCINVAL_REVAL_BEGIN) && (trap_id < TRAP_SCINVAL_REVAL_END))
    ack_magic = SCINREVAL_HANDLER_ACK_SPECIAL;
  else if((trap_id >= TRAP_SCPROT_BEGIN) && (trap_id < TRAP_SCPROT_END))
    ack_magic = SCPROT_HANDLER_ACK_SPECIAL;
  else if((trap_id >= TRAP_SCGRANT_BEGIN) && (trap_id < TRAP_SCGRANT_END))
    ack_magic = SCGRANT_HANDLER_ACK_SPECIAL;
  else if((trap_id >= TRAP_SCTFER_BEGIN) && (trap_id < TRAP_SCTFER_END))
    ack_magic = SCTFER_HANDLER_ACK_SPECIAL;

  switch (trap_id)
  {
  case TRAP_TEST:
  
  case TRAP_SCEXCL_PERM_EXCEPTION:
  case TRAP_SCINVAL_REVAL_PERMS:
  case TRAP_SCPROT_PERM:
  case TRAP_SCGRANT_PERM:
  case TRAP_SCTFER_PERM:
    exp_type = RISCV_EXCP_SECCELL_ILL_PERM;
    break;

  case TRAP_SCEXCL_ADDR_EXCEPTION:
  case TRAP_SCINVAL_REVAL_ADDR:
  case TRAP_SCPROT_ADDR:
  case TRAP_SCGRANT_ADDR:
  case TRAP_SCTFER_ADDR:
    exp_type = RISCV_EXCP_SECCELL_ILL_ADDR;
    break;
  
  case TRAP_SCEXCL_CELL_STATE:
  case TRAP_SCINVAL_REVAL_CELL_STATE:
  case TRAP_SCPROT_INVCELL:
  case TRAP_SCGRANT_INVCELL:
  case TRAP_SCTFER_INVCELL:
    exp_type = RISCV_EXCP_SECCELL_INV_CELL_STATE;
    break;

  case TRAP_SDSWITCH_SDID:
  case TRAP_SCGRANT_SDID:
  case TRAP_SCTFER_SDID:
    exp_type = RISCV_EXCP_SECCELL_INV_SDID;
    break;

  case TRAP_SDSWITCH_ADDR:
    exp_type = RISCV_EXCP_SECCELL_ILL_TGT;
    break;

  case TRAP_SCINVAL_REVAL_FUNC_TRAP:
    exp_type = RISCV_EXCP_STORE_PAGE_FAULT;
    break; 

  /* Unknown/invalid causes will lead to another fault */
  case INVALID_CAUSE:
  default:
    raise_trap();
  }

  trap_generic_test(ack_magic, exp_type, 0, 1);
  trap_skip_inst();
}

/******************************************
 * Wrappers for SecCell instructions
 *****************************************/
bool inline SCExcl(uint64_t addr, uint8_t perm) {
  uint64_t ret;
  excl(ret, addr, perm);
  return ret;
}

/******************************************
 * Tests for SCExcl instruction
 *****************************************/
/* Testing correctness of SCExcl instructions for legal operands */
int scexcl_test_correctness() {
  int mistakes = 0;
  trap_id = INVALID_CAUSE;

  CHECK(get_usid() == 1);
  CHECK(get_urid() == 0);


  for(int cidx = 0; cidx < N_CELLS; cidx++) {
    int rcount = 0, wcount = 0, xcount = 0;
    bool r = (cperms[get_usid()][cidx] & RT_R) == RT_R;
    bool w = (cperms[get_usid()][cidx] & RT_W) == RT_W;
    bool x = (cperms[get_usid()][cidx] & RT_X) == RT_X;

    for(int sdidx = 1; sdidx < M_SDS; sdidx++){
      if((cperms[sdidx][cidx] & RT_R) == RT_R) rcount++;
      if((cperms[sdidx][cidx] & RT_W) == RT_W) wcount++;
      if((cperms[sdidx][cidx] & RT_X) == RT_X) xcount++;
    }

    /* Check only for own permissions => fault otherwise */
    if (r)
      CHECK(SCExcl(cells[cidx].va_start, RT_R) == (rcount == 1));
    if (w)
      CHECK(SCExcl(cells[cidx].va_start, RT_W) == (wcount == 1));
    if (x)
      CHECK(SCExcl(cells[cidx].va_start, RT_X) == (xcount == 1));
  }

  return mistakes;
}


/* Testing exceptions for SCExcl with illegal permissions */
static uint8_t invalid_perms_parameters[] = {
    0x0, 0x1, 0x10, 0x20, 0x40, 0x80
  };

int scexcl_exception_perms() {
  int mistakes = 0;
  trap_id = TRAP_SCEXCL_PERM_EXCEPTION;

  for(uint8_t i = 0; i < sizeof(invalid_perms_parameters); i++) {
    trap_mistakes = 0;
    handler_ack = 0;
    uint8_t test_perm = invalid_perms_parameters[i];
    expected_stval = (((test_perm == 0)? 1: 0) << 8)
                      | test_perm;
    SCExcl(cells[0].va_start, invalid_perms_parameters[i]);

    CHECK(!trap_mistakes && (handler_ack == SCEXCL_HANDLER_ACK_SPECIAL));
  }

  return mistakes;
}

/* Testing exceptions for SCExcl with invalid addresses */
static uint64_t invalid_addresses[] = {
    0x0, 0xf1f1d0d0
  };
int scexcl_exception_addr() {
  int mistakes = 0;
  trap_id = TRAP_SCEXCL_ADDR_EXCEPTION;

  for(uint8_t i = 0; i < sizeof(invalid_addresses)/sizeof(invalid_addresses[0]); i++) {
    trap_mistakes = 0;
    expected_stval = invalid_addresses[i];
    handler_ack = 0;
    SCExcl(invalid_addresses[i], RT_R);

    CHECK(!trap_mistakes && (handler_ack == SCEXCL_HANDLER_ACK_SPECIAL));
  }

  return mistakes;
}

int scexcl_exception_invcell(void) {
  int mistakes = 0;

  uint64_t valid_addr = cells[3].va_start;

  /* Invalidate cell, then test exception */
  inval(valid_addr);
  trap_id = TRAP_SCEXCL_CELL_STATE;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = 0;
  SCExcl(valid_addr, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SCEXCL_HANDLER_ACK_SPECIAL));

  /* Return to original state */
  reval(valid_addr, RT_R | RT_W);

  return mistakes;
}

int scexcl_tests() {
  int scexcl_mistakes = 0;

  scexcl_mistakes += scexcl_test_correctness();
  scexcl_mistakes += scexcl_exception_perms();
  scexcl_mistakes += scexcl_exception_addr();
  scexcl_mistakes += scexcl_exception_invcell();

  return scexcl_mistakes;
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
  register uint64_t ra asm ("ra");

  /* Start at SD 1, switch to SD 2, then back to SD 1 */
  CHECK(get_usid() == 1);
  set_urid(2);
  CHECK(get_usid() == 1);
  CHECK(get_urid() == 2);
  
  tgt_usid = 2;
  tgt_addr = (uint64_t)&&sdswitch_test_functionality0;
  jalrs(ra, tgt_usid, tgt_addr);
  nop(5);
sdswitch_test_functionality0:
  entry(_sdswitch_test_functionality0);
  CHECK(get_usid() == 2);
  CHECK(get_urid() == 1);

  tgt_usid = 1;
  tgt_addr = (uint64_t)&&sdswitch_test_functionality1;
  jalrs(ra, tgt_usid, tgt_addr);
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
  register uint64_t ra asm ("ra");

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
  jalrs(ra, tgt_usid, tgt_addr);
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
  register uint64_t ra asm ("ra");

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
  /* This is required, otherwise the first inst in CHECK() is skipped */
  nop(1);
  CHECK(!trap_mistakes && (handler_ack == SDSWITCH_HANDLER_ACK_SPECIAL));

  /* Try to switch to instruction before entry with jalrs and check fault */
  CHECK(get_usid() == 1);
  /* Illegal tgt should raise exception earlier */
  tgt_usid = 2;
  tgt_addr = (uint64_t)&&sdswitch_test_exception_addr1 - 2;
  expected_stval = tgt_addr;
  handler_ack = 0;
  trap_mistakes = 0;
  jalrs(ra, tgt_usid, tgt_addr);
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
  /* Aliases to first byte of ptable metadata */
  volatile uint8_t *ptr_under_test = (uint8_t *)cells[3].va_start; 
  volatile uint8_t junk = 0;

  CHECK(get_usid() == 1);
  CHECK(is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc7);
  CHECK(*sup_perms_ptr == 0xcf);
  /* This ptr is still valid, and this dereference should not fault.
   * This byte is currently reserved by SecCells, and should be zero */
  trap_id = INVALID_CAUSE;
  CHECK(*ptr_under_test == ptable[0]);

  inval(ptr_under_test);
  CHECK(get_usid() == 1);
  CHECK(!is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc1);
  CHECK(*sup_perms_ptr == 0xce);
  /* This ptr access is now invalid, and this dereference should fault. */
  trap_id = TRAP_SCINVAL_REVAL_FUNC_TRAP;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t)ptr_under_test;
  *ptr_under_test = 0;
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  reval(ptr_under_test, RT_R);
  CHECK(get_usid() == 1);
  CHECK(is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc3);
  CHECK(*sup_perms_ptr == 0xcf);
  /* This ptr is again valid, and this dereference should not fault.
   * This byte is currently reserved by SecCells, and should be zero */
  trap_id = INVALID_CAUSE;
  CHECK(*ptr_under_test == ptable[0]);


  inval(ptr_under_test);
  CHECK(get_usid() == 1);
  CHECK(!is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc1);
  CHECK(*sup_perms_ptr == 0xce);
  /* This ptr access is now invalid, and this dereference should fault. */
  trap_id = TRAP_SCINVAL_REVAL_FUNC_TRAP;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t)ptr_under_test;
  *ptr_under_test = ptable[0];
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  reval(ptr_under_test, RT_R | RT_W);
  CHECK(get_usid() == 1);
  CHECK(is_valid_cell(*desc_ptr));
  CHECK(*perms_ptr == 0xc7);
  CHECK(*sup_perms_ptr == 0xcf);
  /* This ptr is again valid, and this dereference should not fault.
   * This byte is currently reserved by SecCells, and should be zero */
  trap_id = INVALID_CAUSE;
  CHECK(*ptr_under_test == ptable[0]);

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
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCINVAL_REVAL_ADDR;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t) faulty_addr;
  reval(faulty_addr, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  return mistakes;
}

int scinval_reval_exception_celldesc(void) {
  int mistakes = 0;

  uint8_t *valid_addr = (uint8_t *)cells[3].va_start;
  uint8_t *shared_addr = (uint8_t *)cells[2].va_start;

  trap_id = TRAP_SCINVAL_REVAL_CELL_STATE;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = 1; /* Since cell is already valid */
  reval(valid_addr, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCINVAL_REVAL_CELL_STATE;
  handler_ack = 0;
  trap_mistakes = 0;
  inval(valid_addr);
  expected_stval = 0; /* Since cell is already invalid */
  inval(valid_addr);
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));
  reval(valid_addr, RT_R | RT_W);

  trap_id = TRAP_SCINVAL_REVAL_CELL_STATE;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (uint64_t) 2; /* Since cell is shared with other SD */
  inval(shared_addr);
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  return mistakes;
}

int screval_exception_perm(void) {
  int mistakes = 0;
  uint8_t *valid_addr = (uint8_t *)cells[3].va_start;
  uint8_t perms = RT_R | RT_W | RT_X | 0x10;

  /* Pre-invalidate cell */
  inval(valid_addr);

  trap_id = TRAP_SCINVAL_REVAL_PERMS;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = 1 << 8;
  reval(valid_addr, 0);
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCINVAL_REVAL_PERMS;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = perms;
  reval(valid_addr, perms);
  CHECK(!trap_mistakes && (handler_ack == SCINREVAL_HANDLER_ACK_SPECIAL));

  /* Post-revalidate cell */
  reval(valid_addr, RT_R | RT_W);

  return mistakes;
}

int scinval_reval_tests(void) {
  int scinval_reval_mistakes = 0;

  scinval_reval_mistakes += scinval_reval_functionality();
  scinval_reval_mistakes += scinval_reval_exception_addr();
  scinval_reval_mistakes += scinval_reval_exception_celldesc();
  scinval_reval_mistakes += screval_exception_perm();

  return scinval_reval_mistakes;
}

/******************************************
 * Tests for SCProtect instruction
 *****************************************/
int scprotect_test_functionality(void) {
  int mistakes = 0;

  volatile uint8_t *perms_ptr = ptable + (16 * 64) + (64 * 1) + 4;
  uint64_t valid_addr = cells[3].va_start;

  trap_id = INVALID_CAUSE;
  CHECK(*perms_ptr == 0xc7);
  prot(valid_addr, RT_R);
  CHECK(*perms_ptr == 0xc3);
  inval(valid_addr);

  reval(valid_addr, RT_R | RT_W | RT_X);
  CHECK(*perms_ptr == 0xcf);
  prot(valid_addr, RT_R);
  CHECK(*perms_ptr == 0xc3);
  inval(valid_addr);

  reval(valid_addr, RT_R | RT_W | RT_X);
  CHECK(*perms_ptr == 0xcf);
  prot(valid_addr, RT_R | RT_W);
  CHECK(*perms_ptr == 0xc7);
  inval(valid_addr);

  reval(valid_addr, RT_R | RT_W | RT_X);
  CHECK(*perms_ptr == 0xcf);
  prot(valid_addr, RT_R | RT_X);
  CHECK(*perms_ptr == 0xcb);
  inval(valid_addr);

  reval(valid_addr, RT_R | RT_W);
  
  return mistakes;
}

int scprotect_exception_addr(void){
  int mistakes = 0;

  uint64_t faulty_addrs[] = {0xea15f00d, 0xffffffffea15f00d};

  for(unsigned i = 0; i < sizeof(faulty_addrs) / sizeof(faulty_addrs[0]); i++) {
    uint64_t faulty_addr = faulty_addrs[i];
    
    trap_id = TRAP_SCPROT_ADDR;
    handler_ack = 0;
    trap_mistakes = 0;
    expected_stval = faulty_addr;
    prot(faulty_addr, RT_R);
    CHECK(!trap_mistakes && (handler_ack == SCPROT_HANDLER_ACK_SPECIAL));
  }

  return mistakes;
}

int scprotect_exception_perms(void) {
  int mistakes = 0;

  uint64_t valid_addr = cells[3].va_start;
  uint8_t perms;

  trap_id = TRAP_SCPROT_PERM;
  perms = RT_R | RT_W | RT_X | 0x10;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = perms;
  prot(valid_addr, perms);
  CHECK(!trap_mistakes && (handler_ack == SCPROT_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCPROT_PERM;
  perms = RT_R | RT_W | RT_X;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (2 << 8) | perms;
  prot(valid_addr, perms);
  CHECK(!trap_mistakes && (handler_ack == SCPROT_HANDLER_ACK_SPECIAL));

  return mistakes;
}

int scprotect_exception_invcell(void) {
  int mistakes = 0;

  uint64_t valid_addr = cells[3].va_start;

  /* Invalidate cell, then test exception */
  inval(valid_addr);
  trap_id = TRAP_SCPROT_INVCELL;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = 0;
  prot(valid_addr, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SCPROT_HANDLER_ACK_SPECIAL));

  /* Return to original state */
  reval(valid_addr, RT_R | RT_W);

  return mistakes;
}

int scprotect_tests(void) {
  int scprotect_mistakes = 0;

  scprotect_mistakes += scprotect_test_functionality();
  scprotect_mistakes += scprotect_exception_addr();
  scprotect_mistakes += scprotect_exception_perms();
  scprotect_mistakes += scprotect_exception_invcell();

  return scprotect_mistakes;
}

/******************************************
 * Tests for SCProtect instruction
 *****************************************/

int scgrant_test_functionality(void) {
  int mistakes = 0;
  int ci = 4, sdsrc = 1, sddst = 2, tmp;

  volatile uint8_t *src_perms_ptr  = PT(ptable, meta.T, sdsrc, ci);
  volatile uint8_t *dst_perms_ptr  = PT(ptable, meta.T, sddst, ci);
  volatile uint32_t *grant_ptr = GT(ptable, meta.R, meta.T, sdsrc, ci);
  /* valid_addr actually aliases to ptable in physical memory */
  uint64_t valid_addr = cells[3].va_start;
  volatile uint8_t *dst_perms_ptr_alias = PT(((uint8_t *)valid_addr), meta.T, sddst, ci);
  volatile uint32_t *grant_ptr_alias = GT(((uint8_t *)valid_addr), meta.R, meta.T, sdsrc, ci);

  trap_id = INVALID_CAUSE;
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);
  inval(valid_addr);
  reval(valid_addr, RT_R | RT_W | RT_X);
  CHECK(*src_perms_ptr == 0xcf);

  volatile uint8_t *ptr_under_test = (uint8_t *)valid_addr; 
  CHECK(*ptr_under_test == ptable[0]);

  /* Step 1: Grant read-only permission and test it */
  grant(valid_addr, sddst, RT_R);
  CHECK(*src_perms_ptr == 0xcf);
  CHECK(*grant_ptr == G(sddst, RT_R));
  CHECK(*dst_perms_ptr == 0xc1);

  tmp = sddst;
  jals(tmp, scgrant_test_functionality0);
  entry(scgrant_test_functionality0);
  recv(valid_addr, sdsrc, RT_R);
  /* Permissions  check */
  CHECK(*dst_perms_ptr_alias == 0xc3);
  CHECK(*grant_ptr_alias == G(SDINV, 0))
  tmp = sdsrc;
  jals(tmp, scgrant_test_functionality1);
  entry(scgrant_test_functionality1);

  /* Step 2: Grant additional write permission and test it */
  grant(valid_addr, sddst, RT_W);
  CHECK(*src_perms_ptr == 0xcf);
  CHECK(*grant_ptr == G(sddst, RT_W));
  CHECK(*dst_perms_ptr == 0xc3);
  
  tmp = sddst;
  jals(tmp, scgrant_test_functionality2);
  entry(scgrant_test_functionality2);
  recv(valid_addr, sdsrc, RT_W);
  CHECK(*dst_perms_ptr_alias == 0xc7);
  CHECK(*grant_ptr_alias == G(SDINV, 0));
  /* Reset sddst to initial state */
  prot(valid_addr, 0);
  tmp = sdsrc;
  jals(tmp, scgrant_test_functionality3);
  entry(scgrant_test_functionality3);
  /* Reset sddst to initial state */
  prot(valid_addr, RT_R | RT_W);
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  return mistakes;
}

int scgrant_exception_addr(void) {
  int mistakes = 0;
  int ci = 4, sdsrc = 1, sddst = 2;
  volatile uint8_t *src_perms_ptr = PT(ptable, meta.T, sdsrc, ci);
  volatile uint8_t *dst_perms_ptr = PT(ptable, meta.T, sddst, ci);
  volatile uint32_t *grant_ptr = GT(ptable, meta.R, meta.T, sdsrc, ci);
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  uint64_t faulty_addrs[] = {0xea15f00d, 0xffffffffea15f00d};

  for(unsigned i = 0; i < sizeof(faulty_addrs) / sizeof(faulty_addrs[0]); i++) {
    uint64_t faulty_addr = faulty_addrs[i];
    
    trap_id = TRAP_SCGRANT_ADDR;
    handler_ack = 0;
    trap_mistakes = 0;
    expected_stval = faulty_addr;
    grant(faulty_addr, sddst, RT_R);
    CHECK(!trap_mistakes && (handler_ack == SCGRANT_HANDLER_ACK_SPECIAL));
    CHECK(*grant_ptr == G(SDINV, 0));
  }
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  return mistakes;
}

int scgrant_exception_sdid(void) {
  int mistakes = 0;
  int ci = 4, sdsrc = 1, sddst = 2;
  volatile uint8_t *src_perms_ptr = PT(ptable, meta.T, 1, ci);
  volatile uint8_t *dst_perms_ptr = PT(ptable, meta.T, 2, ci);
  uint64_t valid_addr = cells[3].va_start;
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  uint64_t tgt_sds[] = {0, 1024};
  for(int i = 0; i < sizeof(tgt_sds) / sizeof(tgt_sds[0]); i++) {
    uint64_t tgt_sd = tgt_sds[i];

    trap_id = TRAP_SCGRANT_SDID;
    handler_ack = 0;
    trap_mistakes = 0;
    expected_stval = tgt_sd;
    grant(valid_addr, tgt_sd, RT_R);
    CHECK(!trap_mistakes && (handler_ack == SCGRANT_HANDLER_ACK_SPECIAL));
  }
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  return mistakes;
}

int scgrant_exception_perms(void) {
  int mistakes = 0;
  int ci = 4, sdsrc = 1, sddst = 2;
  volatile uint8_t *src_perms_ptr = PT(ptable, meta.T, sdsrc, ci);
  volatile uint8_t *dst_perms_ptr = PT(ptable, meta.T, sddst, ci);
  uint64_t valid_addr = cells[3].va_start;
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);
  uint64_t tgt_sd = 2;
  uint8_t perms;

  trap_id = TRAP_SCGRANT_PERM;
  perms = RT_R | RT_W | RT_X | 0x10;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = perms;
  grant(valid_addr, tgt_sd, perms);
  CHECK(!trap_mistakes && (handler_ack == SCGRANT_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCGRANT_PERM;
  perms = 0;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (1 << 8);
  grant(valid_addr, tgt_sd, perms);
  CHECK(!trap_mistakes && (handler_ack == SCGRANT_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCGRANT_PERM;
  perms = RT_R | RT_W | RT_X;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (2 << 8) | perms;
  grant(valid_addr, tgt_sd, perms);
  CHECK(!trap_mistakes && (handler_ack == SCGRANT_HANDLER_ACK_SPECIAL));

  /* Reset to initial state */
  tgt_sd = 2;
  jals(tgt_sd, scgrant_exception_perms0);
  entry(scgrant_exception_perms0);
  prot(valid_addr, 0);
  tgt_sd = 1;
  jals(tgt_sd, scgrant_exception_perms1);
  entry(scgrant_exception_perms1);
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);
  CHECK(get_usid() == 1);

  return mistakes;
}

int scgrant_exception_invcell(void) {
  int mistakes = 0;

  int ci = 4, sdsrc = 1, sddst = 2;
  volatile uint8_t *src_perms_ptr = PT(ptable, meta.T, sdsrc, ci);
  volatile uint8_t *dst_perms_ptr = PT(ptable, meta.T, sddst, ci);
  uint64_t valid_addr = cells[3].va_start;
  uint64_t tgt_sd = 2;

  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  /* Invalidate cell, then test exception */
  inval(valid_addr);
  trap_id = TRAP_SCGRANT_INVCELL;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = 0;
  grant(valid_addr, tgt_sd, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SCGRANT_HANDLER_ACK_SPECIAL));

  /* Return to original state */
  reval(valid_addr, RT_R | RT_W);

  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  return mistakes;
}

int scgrant_tests(void) {
  int scgrant_mistakes = 0;

  scgrant_mistakes += scgrant_test_functionality();
  scgrant_mistakes += scgrant_exception_addr();
  scgrant_mistakes += scgrant_exception_sdid();
  scgrant_mistakes += scgrant_exception_perms();
  scgrant_mistakes += scgrant_exception_invcell();

  return scgrant_mistakes;
}

/******************************************
 * Tests for SCTfer instruction
 *****************************************/

int sctfer_test_functionality(void) {
  int mistakes = 0;
  int ci = 4, sdsrc = 1, sddst = 2, tmp;

  volatile uint8_t *src_perms_ptr = PT(ptable, meta.T, sdsrc, ci);
  volatile uint8_t *dst_perms_ptr = PT(ptable, meta.T, sddst, ci);
  volatile uint32_t *grant_ptr = GT(ptable, meta.R, meta.T, sdsrc, ci);
  uint64_t valid_addr = cells[3].va_start;
  /* valid_addr actually aliases to ptable in physical memory */
  volatile uint8_t *dst_perms_ptr_alias = PT(((uint8_t *)valid_addr), meta.T, sddst, ci);
  volatile uint32_t *grant_ptr_alias = GT(((uint8_t *)valid_addr), meta.R, meta.T, sdsrc, ci);

  /* Check initial state */
  trap_id = INVALID_CAUSE;
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);
  inval(valid_addr);
  reval(valid_addr, RT_R | RT_W | RT_X);
  CHECK(*src_perms_ptr == 0xcf);
  CHECK(get_usid() == 1);

  /* Check one transfer */
  tfer(valid_addr, sddst, RT_R);
  CHECK(*src_perms_ptr == 0xc1);
  CHECK(*grant_ptr == G(sddst, RT_R));
  CHECK(*dst_perms_ptr == 0xc1);
  CHECK(get_usid() == 1);

  tmp = sddst;
  jals(tmp, sctfer_test_functionality0);
  entry(sctfer_test_functionality0);
  recv(valid_addr, sdsrc, RT_R);
  /* Permissions  check */
  CHECK(*dst_perms_ptr_alias == 0xc3);
  CHECK(*grant_ptr_alias == G(SDINV, 0))
  tmp = sdsrc;
  jals(tmp, sctfer_test_functionality1);
  entry(sctfer_test_functionality1);

  /* Restore to initial state */
  tmp = sddst;
  jals(tmp, sctfer_test_functionality2);
  entry(sctfer_test_functionality2);
  inval(valid_addr);
  tmp = sdsrc;
  jals(tmp, sctfer_test_functionality3);
  entry(sctfer_test_functionality3);
  reval(valid_addr, RT_R | RT_W);

  /* Check initial state */
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);
  CHECK(*grant_ptr_alias == G(SDINV, 0))
  CHECK(get_usid() == 1);

  /* Check another transfer */
  tfer(valid_addr, sddst, RT_R | RT_W);
  CHECK(*src_perms_ptr == 0xc1);
  CHECK(*grant_ptr == G(sddst, RT_R | RT_W));
  CHECK(*dst_perms_ptr == 0xc1);
  CHECK(get_usid() == 1);

  /* Restore to initial state */
  tmp = sddst;
  jals(tmp, sctfer_test_functionality4);
  entry(sctfer_test_functionality4);
  recv(valid_addr, sdsrc, RT_R | RT_W);
  inval(valid_addr);
  tmp = sdsrc;
  jals(tmp, sctfer_test_functionality5);
  entry(sctfer_test_functionality5);
  reval(valid_addr, RT_R | RT_W);

  return mistakes;
}

int sctfer_exception_addr(void) {
  int mistakes = 0;

  uint64_t tgt_sd = 2;
  uint64_t faulty_addrs[] = {0xea15f00d, 0xffffffffea15f00d};
  for(unsigned i = 0; i < sizeof(faulty_addrs) / sizeof(faulty_addrs[0]); i++) {
    uint64_t faulty_addr = faulty_addrs[i];

    trap_id = TRAP_SCTFER_ADDR;
    handler_ack = 0;
    trap_mistakes = 0;
    expected_stval = faulty_addr;
    tfer(faulty_addr, tgt_sd, RT_R);
    CHECK(!trap_mistakes && (handler_ack == SCTFER_HANDLER_ACK_SPECIAL));
  }

  return mistakes;
}

int sctfer_exception_perms(void) {
  int mistakes = 0;

  volatile uint8_t *src_perms_ptr = ptable + (16 * 64) + (64 * 1) + 4;
  volatile uint8_t *dst_perms_ptr = ptable + (16 * 64) + (64 * 2) + 4;
  uint64_t valid_addr = cells[3].va_start;
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);
  uint64_t tgt_sd = 2;
  uint8_t perms;

  trap_id = TRAP_SCTFER_PERM;
  perms = RT_R | RT_W | RT_X | 0x10;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = perms;
  tfer(valid_addr, tgt_sd, perms);
  CHECK(!trap_mistakes && (handler_ack == SCTFER_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCTFER_PERM;
  perms = 0;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (1 << 8);
  tfer(valid_addr, tgt_sd, perms);
  CHECK(!trap_mistakes && (handler_ack == SCTFER_HANDLER_ACK_SPECIAL));

  trap_id = TRAP_SCTFER_PERM;
  perms = RT_R | RT_W | RT_X;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = (2 << 8) | perms;
  tfer(valid_addr, tgt_sd, perms);
  CHECK(!trap_mistakes && (handler_ack == SCTFER_HANDLER_ACK_SPECIAL));

  /* Reset to initial state */
  tgt_sd = 2;
  jals(tgt_sd, sctfer_exception_perms0);
  entry(sctfer_exception_perms0);
  prot(valid_addr, 0);
  tgt_sd = 1;
  jals(tgt_sd, sctfer_exception_perms1);
  entry(sctfer_exception_perms1);
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);
  CHECK(get_usid() == 1);

  return mistakes;
}

int sctfer_exception_sdid(void) {
  int mistakes = 0;

  volatile uint8_t *src_perms_ptr = ptable + (16 * 64) + (64 * 1) + 4;
  volatile uint8_t *dst_perms_ptr = ptable + (16 * 64) + (64 * 2) + 4;
  uint64_t valid_addr = cells[3].va_start;
  CHECK(*src_perms_ptr == 0xc7);
  CHECK(*dst_perms_ptr == 0xc1);

  uint64_t tgt_sds[] = {0, 1024};
  for(int i = 0; i < sizeof(tgt_sds) / sizeof(tgt_sds[0]); i++) {
    uint64_t tgt_sd = tgt_sds[i];

    trap_id = TRAP_SCTFER_SDID;
    handler_ack = 0;
    trap_mistakes = 0;
    expected_stval = tgt_sd;
    tfer(valid_addr, tgt_sd, RT_R);
    CHECK(!trap_mistakes && (handler_ack == SCTFER_HANDLER_ACK_SPECIAL));
  }

  return mistakes;

}

int sctfer_exception_invcell(void) {
  int mistakes = 0;

  uint64_t valid_addr = cells[3].va_start;
  uint64_t tgt_sd = 2;

  /* Invalidate cell, then test exception */
  inval(valid_addr);
  trap_id = TRAP_SCTFER_INVCELL;
  handler_ack = 0;
  trap_mistakes = 0;
  expected_stval = 0;
  tfer(valid_addr, tgt_sd, RT_R);
  CHECK(!trap_mistakes && (handler_ack == SCTFER_HANDLER_ACK_SPECIAL));

  /* Return to original state */
  reval(valid_addr, RT_R | RT_W);

  return mistakes;
}

int sctfer_tests(void) {
  int sctfer_mistakes = 0;

  sctfer_mistakes += sctfer_test_functionality();
  sctfer_mistakes += sctfer_exception_addr();
  sctfer_mistakes += sctfer_exception_perms();
  sctfer_mistakes += sctfer_exception_sdid();
  sctfer_mistakes += sctfer_exception_invcell();

  return sctfer_mistakes;
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
  mistakes += scexcl_tests();
  mistakes += sdswitch_tests();
  mistakes += scinval_reval_tests();
  mistakes += scprotect_tests();
  mistakes += scgrant_tests();
  mistakes += sctfer_tests();

  if(mistakes)
    wrong();
  else
    correct();
}
