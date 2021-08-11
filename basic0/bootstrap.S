#include "init.h"
#include "test.h"

.text

.global _entry
_entry:
  # Setup stack
  la t0, ptable
  li t1, 0x20000     # BIOS_SIZE 0x2000
  sub t0, t0, t1
  li t1, 0x200000    # RAM_SIZE 0x200000
  add t0, t0, t1
  /* Reserve a token 16B at the top of the RAM,
   * and denote the rest as stack */
  add t0, t0, -16
  mv sp, t0

  # Setup PTable and drop into virtual memory
  /* Move into virtual memory using cool Linux trick:
   *
   * Setup STVEC to VA of instruction at next marker '1'.
   * Then write SATP, and flush. 
   * The SATP update will cause a fault, as the physical address PC
   * is invalid, moving to stvec. 
   * Now executing in virtual mem, at instruction '1'.
   */
  call setup_vm
  la t0, 1f
  li t1, 0x100000000 # VM offset
  add t0, t0, t1
  csrw stvec, t0
  li t0, 0
  csrw usid, t0
  li t0, 0xf         # SATP_MODE 0xf 
  slli t0, t0, 60
  la t1, ptable
  srli t1, t1, 12
  or t0, t0, t1
  csrw satp, t0
  sfence.vma  
1:
  nop
  la t0, exception_handler
  csrw stvec, t0
  # Fix stack pointer
  li t0, 0x100000000 # VM offset
  add sp, sp, t0

  # Drop into test as user with SD1
  la t0, test
  csrw sepc, t0
  li t0, 1
  csrw urid, t0
drop_to_test:
  sret

exception_handler:
  j exception_handler