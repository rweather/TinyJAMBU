
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

COMMON_INCLUDES = crypto_auth.h crypto_hash.h api.h
HASHREF_SOURCES = hash.c genkat_hash.c state.c
HMACREF_SOURCES = hmac.c hash.c genkat_auth.c state.c

TARGETS = bin/hashref bin/hmacref

all: $(TARGETS)

bin/hashref: $(HASHREF_SOURCES) $(COMMON_INCLUDES)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(HASHREF_SOURCES) $(LDFLAGS)

bin/hmacref: $(HMACREF_SOURCES) $(COMMON_INCLUDES)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(HMACREF_SOURCES) $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/hashref
	mv LWC_HASH_KAT_256.txt ../../test/kat/TinyJAMBU-HASH.txt
	bin/hmacref
	mv LWC_AUTH_KAT_256_256.txt ../../test/kat/TinyJAMBU-HMAC.txt
