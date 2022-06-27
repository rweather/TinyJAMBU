
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/tinyjambu_xtensa

all: $(TARGETS)

bin/tinyjambu_xtensa: tinyjambu_xtensa.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/tinyjambu_xtensa 128 >../../src/tinyjambu-128-asm-xtensa.S
	bin/tinyjambu_xtensa 192 >../../src/tinyjambu-192-asm-xtensa.S
	bin/tinyjambu_xtensa 256 >../../src/tinyjambu-256-asm-xtensa.S
