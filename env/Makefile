# SPDX-License-Identifier: GPL-2.0+
#
# (C) Copyright 2004-2006
# Wolfgang Denk, DENX Software Engineering, wd@denx.de.

obj-y += common.o env.o env_ctx_uboot.o

ifndef CONFIG_SPL_BUILD
obj-y += attr.o
obj-y += callback.o
obj-y += flags.o
obj-$(CONFIG_ENV_DRV_EEPROM) += eeprom.o
extra-$(CONFIG_ENV_IS_EMBEDDED) += embedded.o
obj-$(CONFIG_ENV_DRV_EEPROM) += embedded.o
extra-$(CONFIG_ENV_DRV_FLASH) += embedded.o
obj-$(CONFIG_ENV_DRV_NVRAM) += embedded.o
obj-$(CONFIG_ENV_DRV_NVRAM) += nvram.o
obj-$(CONFIG_ENV_DRV_ONENAND) += onenand.o
obj-$(CONFIG_ENV_DRV_SATA) += sata.o
obj-$(CONFIG_ENV_DRV_REMOTE) += remote.o
obj-$(CONFIG_ENV_DRV_UBI) += ubi.o
else
obj-$(CONFIG_$(SPL_TPL_)ENV_SUPPORT) += attr.o
obj-$(CONFIG_$(SPL_TPL_)ENV_SUPPORT) += flags.o
obj-$(CONFIG_$(SPL_TPL_)ENV_SUPPORT) += callback.o
endif

obj-$(CONFIG_$(SPL_TPL_)ENV_IS_NOWHERE) += nowhere.o
obj-$(CONFIG_$(SPL_TPL_)ENV_DRV_MMC) += mmc.o
obj-$(CONFIG_$(SPL_TPL_)ENV_DRV_FAT) += fat.o
obj-$(CONFIG_$(SPL_TPL_)ENV_DRV_EXT4) += ext4.o
obj-$(CONFIG_$(SPL_TPL_)ENV_DRV_NAND) += nand.o
obj-$(CONFIG_$(SPL_TPL_)ENV_DRV_SPI_FLASH) += sf.o
obj-$(CONFIG_$(SPL_TPL_)ENV_DRV_FLASH) += flash.o

CFLAGS_embedded.o := -Wa,--no-warn -DENV_CRC=$(shell tools/envcrc 2>/dev/null)
