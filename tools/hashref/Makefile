
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

COMMON_INCLUDES = crypto_hash.h api.h
COMMON_SOURCES = genkat_hash.c state.c
COMMON_ALL = $(COMMON_INCLUDES) $(COMMON_SOURCES)

TARGETS = bin/hashref

all: $(TARGETS)

bin/hashref: hash.c $(COMMON_ALL)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ hash.c $(COMMON_SOURCES) $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/hashref
	mv LWC_HASH_KAT_256.txt ../../test/kat/TinyJAMBU-HASH.txt
