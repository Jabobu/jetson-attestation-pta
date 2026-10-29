# SPDX-License-Identifier: BSD-2-Clause
O ?= .
CC := $(CROSS_COMPILE)gcc
CPPFLAGS += -I../ta/include -I$(OPTEE_CLIENT_EXPORT)/include
CFLAGS += -Wall -Wextra -O2
LDLIBS += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec
.PHONY: all
all: $(O)/attestation_example
$(O)/attestation_example: attestation_example.c ../ta/include/attestation_example.h
	mkdir -p $(O)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
