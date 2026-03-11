# Makefile for Cryptography Lab (C / OpenSSL)

CC      = gcc
COMMON  = common.c

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
    CFLAGS  = -Wall -Wextra -O2 -I $(OPENSSL_PREFIX)/include
    LDFLAGS = -L $(OPENSSL_PREFIX)/lib -lssl -lcrypto
else
    CFLAGS  = -Wall -Wextra -O2
    LDFLAGS = -lssl -lcrypto
endif

ALL = 1_encrypt_text 2_encrypt_image 3_sign_digest

.PHONY: all clean

all: $(ALL)

1_encrypt_text: 1_encrypt_text.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

2_encrypt_image: 2_encrypt_image.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

3_sign_digest: 3_sign_digest.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(ALL)
	rm -rf output
