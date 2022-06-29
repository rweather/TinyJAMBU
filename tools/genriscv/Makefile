
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/tinyjambu_riscv32e \
	bin/tinyjambu_riscv32i \
	bin/tinyjambu_riscv64i

all: $(TARGETS)

bin/tinyjambu_riscv32e: tinyjambu_riscv32.c ../common/copyright.h
	@mkdir -p bin
	$(CC) -DRV32E $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/tinyjambu_riscv32i: tinyjambu_riscv32.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/tinyjambu_riscv64i: tinyjambu_riscv32.c ../common/copyright.h
	@mkdir -p bin
	$(CC) -DRV64I_PLATFORM $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/tinyjambu_riscv32e 128 >../../src/backend/tinyjambu-128-asm-riscv32e.S
	bin/tinyjambu_riscv32e 192 >../../src/backend/tinyjambu-192-asm-riscv32e.S
	bin/tinyjambu_riscv32e 256 >../../src/backend/tinyjambu-256-asm-riscv32e.S
	bin/tinyjambu_riscv32i 128 >../../src/backend/tinyjambu-128-asm-riscv32i.S
	bin/tinyjambu_riscv32i 192 >../../src/backend/tinyjambu-192-asm-riscv32i.S
	bin/tinyjambu_riscv32i 256 >../../src/backend/tinyjambu-256-asm-riscv32i.S
	bin/tinyjambu_riscv64i 128 >../../src/backend/tinyjambu-128-asm-riscv64i.S
	bin/tinyjambu_riscv64i 192 >../../src/backend/tinyjambu-192-asm-riscv64i.S
	bin/tinyjambu_riscv64i 256 >../../src/backend/tinyjambu-256-asm-riscv64i.S
