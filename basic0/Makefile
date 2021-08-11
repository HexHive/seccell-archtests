AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
CC=riscv64-unknown-elf-gcc
CFLAGS=-g -O1 -fPIC -fno-builtin -mcmodel=medany
ASFLAGS=-g
LDFLAGS=

.PHONY: ALL
all: fpga_test

fpga_test: bootstrap.o test.o init.o util.o linker.ld
	$(LD) $(LDFLAGS) -o fpga_test -T linker.ld bootstrap.o test.o init.o util.o

test.o: test.c test.h

# init.o is a special case, compiled without PIC to avoid having GOT
# However, as long as functions in init.c are assured to run in PA space,
# this will work properly
init.o: init.c init.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-PIC -c -o $@ $<

util.o: util.c util.h

bootstrap.s: bootstrap.S test.h init.h

bootstrap.o: bootstrap.s

.PHONY: clean
clean:
	rm -f bootstrap.s bootstrap.o test.o init.o util.o fpga_test
