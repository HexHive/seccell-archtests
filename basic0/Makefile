AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld
CC=riscv64-unknown-elf-gcc
CFLAGS=-g -fPIC 
ASFLAGS=-g

all: fpga_test

fpga_test: bootstrap.o test.o linker.ld
	$(LD) -o fpga_test -T linker.ld bootstrap.o test.o

test.o: test.c test.h

bootstrap.s: bootstrap.S test.h

bootstrap.o: bootstrap.s

.PHONY: clean
clean:
	rm -f bootstrap.o test.o fpga_test
