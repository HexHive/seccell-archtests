AS=riscv64-unknown-elf-as
LD=riscv64-unknown-elf-ld

all: fpga_test

fpga_test: fpga_test.o linker.ld
	$(LD) -o fpga_test -T linker.ld fpga_test.o

fpga_test.o: fpga_test.S
	$(AS) -o fpga_test.o fpga_test.S

.PHONY: clean
clean:
	rm -f fpga_test.o fpga_test