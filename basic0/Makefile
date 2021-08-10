AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
CC=riscv64-unknown-elf-gcc
CFLAGS=-g -fPIC -O3
ASFLAGS=-g

.PHONY: ALL
all: fpga_test

fpga_test: bootstrap.o test.o init.o util.o linker.ld
	$(LD) -o fpga_test -T linker.ld bootstrap.o test.o init.o util.o

test.o: test.c test.h

init.o: init.c init.h

util.o: util.c util.h

bootstrap.s: bootstrap.S test.h init.h

bootstrap.o: bootstrap.s

.PHONY: clean
clean:
	rm -f bootstrap.s bootstrap.o test.o init.o util.o fpga_test
