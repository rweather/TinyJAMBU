
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/tinyjambu_armv7m

all: $(TARGETS)

bin/tinyjambu_armv7m: tinyjambu_armv7m.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/tinyjambu_armv7m 128 >../../src/tinyjambu-128-asm-armv7m.S
	bin/tinyjambu_armv7m 192 >../../src/tinyjambu-192-asm-armv7m.S
	bin/tinyjambu_armv7m 256 >../../src/tinyjambu-256-asm-armv7m.S
