
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/tinyjambu_armv6 \
	bin/tinyjambu_armv6m \
	bin/tinyjambu_armv7m

all: $(TARGETS)

bin/tinyjambu_armv6: tinyjambu_armv7m.c ../common/copyright.h
	@mkdir -p bin
	$(CC) -DFORCE_ARM_MODE $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/tinyjambu_armv6m: tinyjambu_armv6m.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/tinyjambu_armv7m: tinyjambu_armv7m.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/tinyjambu_armv6 128 >../../src/backend/tinyjambu-128-asm-armv6.S
	bin/tinyjambu_armv6 192 >../../src/backend/tinyjambu-192-asm-armv6.S
	bin/tinyjambu_armv6 256 >../../src/backend/tinyjambu-256-asm-armv6.S
	bin/tinyjambu_armv6m 128 >../../src/backend/tinyjambu-128-asm-armv6m.S
	bin/tinyjambu_armv6m 192 >../../src/backend/tinyjambu-192-asm-armv6m.S
	bin/tinyjambu_armv6m 256 >../../src/backend/tinyjambu-256-asm-armv6m.S
	bin/tinyjambu_armv7m 128 >../../src/backend/tinyjambu-128-asm-armv7m.S
	bin/tinyjambu_armv7m 192 >../../src/backend/tinyjambu-192-asm-armv7m.S
	bin/tinyjambu_armv7m 256 >../../src/backend/tinyjambu-256-asm-armv7m.S
