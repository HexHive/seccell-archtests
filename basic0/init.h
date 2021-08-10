
#ifdef __ASSEMBLER__
.global ptable
.global setup_vm
#else
#include <inttypes.h>

extern uint8_t ptable[0x1000];
void setup_vm();
#endif
