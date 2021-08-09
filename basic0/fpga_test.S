#define SATP_MODE 0xf
#define RAM_SIZE 0x200000

/****************** Initial data section ******************/
.data
data_start_addr:
ptable: .zero 0x1000

helloworld:  .ascii "Hello World!"

/****************** Code section ******************/
.text
.global _entry
text_start_addr:

_entry:
  call vm_init

exception_handler:
  nop

/* Writes a cell description (valid, !deleted) to memory 
 * a0: Address
 * a1: VA start
 * a2: VA end
 * a3: PA start
 * 
 */
write_cell:
  mv t0, a2
  srli t0, t0, 12
  slli t0, t0, 36
  mv t1, a1
  slli t1, t1, 16
  srli t1, t1, 28
  or t0, t0, t1
  sd t0, (a0)

  mv t0, a2
  slli t0, t0, 16
  srli t0, t0, 56
  mv t1, a3
  slli t1, t1, 8
  srli t1, t1, 20
  slli t1, t1, 8
  or t0, t0, t1
  li t1, 1
  slli t1, t1, 62
  or t0, t0, t1
  sd t0, 8(a0)

  ret

/* Sets up ptable with three mappings, two user secdivs (0, 1 and 2):
 * - Data cell (ro) (Why? because why not? just to test faults perhaps)
 * - Text cell
 * - Free use cell
 *
 * Constant offset of 0x1 0000 0000 for (VA - PA).
 */
setup_ptable:
  la t0, ptable

  /* Set N = 4 (including metacell), M = 3, T = 1 */
  li t1, 0x4
  sw t1, (t0)
  li t1, 0x3
  sw t1, 4(t0)
  li t1, 0x1
  sw t1, 8(t0)

  /* t1 = size of first cell, t2 = offset */
  li t1, 0x4000
  li t2, 0x100000000

  /* Setup first cell:  VA=0x1 8000 0000, PA=.data, size=0x4000 */
  addi t0, t0, 0x10
  mv a0, t0
  la a3, data_start_addr
  mv a1, a3
  add a1, a1, t2
  mv a2, a1
  add a2, a2, t1
  call write_cell

  /* Setup second cell: VA=0x1 8000 4000, PA=.text, size=0x4000 */
  addi t0, t0, 0x10
  mv a0, t0
  la a3, text_start_addr
  mv a1, a3
  add a1, a1, t2
  mv a2, a1
  add a2, a2, t1
  call write_cell

  /* Setup third cell: VA=0x1 8000 8000, PA=.remaining, size=0x1f 8000 */
  addi t0, t0, 0x10
  mv a0, t0
  la a3, text_start_addr
  add a3, a3, t1
  mv a1, a3
  add a1, a1, t2
  la a2, data_start_addr
  add a2, a2, t2
  /* RAM_SIZE 0x200000 */
  li t3, 0x200000
  add a2, a2, t3
  call write_cell

  /* Write permissions */
  la t0, ptable
  addi t0, t0, 0x400

  /* Permissions for supervisor: rwx (cf), r-x (cb), rwx (cf) */
  mv t1, t0
  li t2, 0xcf
  sb t2, 1(t1)
  sb t2, 3(t1)
  li t2, 0xcb
  sb t1, 2(t1)

  /* Permissions for secdiv SD1: r-- (c3), r-x (cb), rw- (c7) */
  addi t1, t1, 64
  li t2, 0xc3
  sb t2, 1(t1)
  li t2, 0xcb
  sb t2, 2(t1)
  li t2, 0xc7
  sb t2, 3(t1)

  /* Permissions for secdiv SD2: --- (c1), r-x (cb), --- (c1) */
  addi t1, t1, 64
  li t2, 0xc1
  sb t2, 1(t1)
  sb t2, 3(t1)
  li t2, 0xcb
  sb t2, 2(t2)

  ret

vm_init:
  call setup_ptable
  
  /* Move into virtual memory using cool Linux trick:
   *
   * Setup STVEC to VA of instruction at next marker '1'.
   * Then write SATP, and flush. 
   * The SATP update will cause a fault, as the physical address PC
   * is invalid, moving to stvec. 
   * Now executing in virtual mem, at instruction '1'.
   */
  la t0, 1f
  li t1, 0x100000000
  add t0, t0, t1
  csrw stvec, t0
  /* SATP_MODE 0xf */
  li t0, 0xf
  slli t0, t0, 60
  la t1, ptable
  srli t1, t1, 12
  or t0, t0, t1
  csrw satp, t0
  sfence.vma  
1:
  nop
  ret


