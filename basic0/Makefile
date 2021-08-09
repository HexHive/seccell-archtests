AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld

all: fpga_test

fpga_test: bootstrap.o linker.ld
	$(LD) -o fpga_test -T linker.ld bootstrap.o

bootstrap.o: bootstrap.S
	$(AS) -o bootstrap.o bootstrap.S

.PHONY: clean
clean:
	rm -f bootstrap.o fpga_test
