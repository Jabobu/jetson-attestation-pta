# SPDX-License-Identifier: BSD-2-Clause
O ?= $(CURDIR)/out
O_ABS := $(abspath $(O))
.PHONY: all clean
all:
	$(MAKE) -C ta TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" CROSS_COMPILE="$(CROSS_COMPILE)" O="$(O_ABS)/ta"
	$(MAKE) -C host OPTEE_CLIENT_EXPORT="$(OPTEE_CLIENT_EXPORT)" CROSS_COMPILE="$(CROSS_COMPILE)" O="$(O_ABS)/host"
clean:
	rm -rf "$(O_ABS)"
