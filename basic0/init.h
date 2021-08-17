
#define VA_OFFSET 0x100000000ul
#define BIOS_SIZE 0x40000
#define RAM_SIZE  0x200000

#ifdef __ASSEMBLER__
.global ptable
.global setup_vm
#else
#include <inttypes.h>

extern uint8_t ptable[0x1000];
void setup_vm();
#endif
