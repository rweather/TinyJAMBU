
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

COMMON_INCLUDES = crypto_aead.h api.h
COMMON_SOURCES = genkat_aead.c
COMMON_ALL = $(COMMON_INCLUDES) $(COMMON_SOURCES)

TARGETS = \
	bin/sivref-128 \
	bin/sivref-192 \
	bin/sivref-256

all: $(TARGETS)

bin/sivref-128: encrypt-128.c $(COMMON_ALL)
	@mkdir -p bin
	$(CC) -DCRYPTO_KEYBYTES=16 $(CFLAGS) -o $@ encrypt-128.c $(COMMON_SOURCES) $(LDFLAGS)

bin/sivref-192: encrypt-192.c $(COMMON_ALL)
	@mkdir -p bin
	$(CC) -DCRYPTO_KEYBYTES=24 $(CFLAGS) -o $@ encrypt-192.c $(COMMON_SOURCES) $(LDFLAGS)

bin/sivref-256: encrypt-256.c $(COMMON_ALL)
	@mkdir -p bin
	$(CC) -DCRYPTO_KEYBYTES=32 $(CFLAGS) -o $@ encrypt-256.c $(COMMON_SOURCES) $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/sivref-128
	mv LWC_AEAD_KAT_128_96.txt ../../test/kat/TinyJAMBU-128-SIV.txt
	bin/sivref-192
	mv LWC_AEAD_KAT_192_96.txt ../../test/kat/TinyJAMBU-192-SIV.txt
	bin/sivref-256
	mv LWC_AEAD_KAT_256_96.txt ../../test/kat/TinyJAMBU-256-SIV.txt
