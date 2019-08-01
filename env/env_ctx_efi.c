// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 Linaro Limited
 *		Author: AKASHI Takahiro
 */

#include <common.h>
#include <env_flags.h>
#include <env_internal.h>
#include <search.h>

DECLARE_GLOBAL_DATA_PTR;

struct hsearch_data efi_htab = {
#if CONFIG_IS_ENABLED(ENV_SUPPORT)
	/* defined in flags.c, only compile with ENV_SUPPORT */
	.change_ok = env_flags_validate,
#endif
};

struct hsearch_data efi_volatile_htab = {
#if CONFIG_IS_ENABLED(ENV_SUPPORT)
	/* defined in flags.c, only compile with ENV_SUPPORT */
	.change_ok = env_flags_validate,
#endif
};

static int env_drv_init_efi(struct env_context *ctx, enum env_location loc)
{
	__maybe_unused int ret;

	switch (loc) {
#ifdef CONFIG_ENV_EFI_IS_IN_FLASH
	case ENVL_FLASH: {
		env_t *env_ptr;
		env_t *flash_addr;
		ulong end_addr;
		env_t *flash_addr_new;
		ulong end_addr_new;

#if defined(CONFIG_ENV_EFI_ADDR_REDUND) && defined(CMD_SAVEENV) || \
	!defined(CONFIG_ENV_EFI_ADDR_REDUND) && defined(INITENV)
#ifdef ENV_IS_EMBEDDED
		/* FIXME: not allowed */
		env_ptr = NULL;
#else /* ! ENV_IS_EMBEDDED */

		env_ptr = (env_t *)CONFIG_ENV_EFI_ADDR;
#endif /* ENV_IS_EMBEDDED */
#else
		env_ptr = NULL;
#endif
		flash_addr = (env_t *)CONFIG_ENV_EFI_ADDR;

/* CONFIG_ENV_EFI_ADDR is supposed to be on sector boundary */
		end_addr = CONFIG_ENV_EFI_ADDR + CONFIG_ENV_EFI_SECT_SIZE - 1;

#ifdef CONFIG_ENV_EFI_ADDR_REDUND
		flash_addr_new = (env_t *)CONFIG_ENV_EFI_ADDR_REDUND;
/* CONFIG_ENV_EFI_ADDR_REDUND is supposed to be on sector boundary */
		end_addr_new = CONFIG_ENV_EFI_ADDR_REDUND
					+ CONFIG_ENV_EFI_SECT_SIZE - 1;
#else
		flash_addr_new = NULL;
		end_addr_new = 0;
#endif /* CONFIG_ENV_EFI_ADDR_REDUND */

		ret = env_flash_init_params(ctx, env_ptr, flash_addr, end_addr,
					    flash_addr_new, end_addr_new,
					    NULL);
		if (ret)
			return -ENOENT;

		return 0;
		}
#endif
#ifdef CONFIG_ENV_EFI_IS_IN_FAT
	case ENVL_FAT: {
		ret = env_fat_init_params(ctx,
					  CONFIG_ENV_EFI_FAT_INTERFACE,
					  CONFIG_ENV_EFI_FAT_DEVICE_AND_PART,
					  CONFIG_ENV_EFI_FAT_FILE);

		return 0;
		}
#endif
#ifdef CONFIG_ENV_DRV_NONE
	case ENVL_NOWHERE:
#ifdef CONFIG_ENV_EFI_IS_NOWHERE
		/* TODO: what we should do */

		return -ENOENT;
#else
		return -ENOENT;
#endif
#endif
	default:
		return -ENOENT;
	}
}

/*
 * Env context for UEFI variables
 */
U_BOOT_ENV_CONTEXT(efi) = {
	.name = "efi",
	.htab = &efi_htab,
	.env_size = 0x10000, /* TODO: make this configurable */
	.drv_init = env_drv_init_efi,
};

static int env_ctx_init_efi_volatile(struct env_context *ctx)
{
	/* Dummy table creation, or hcreate_r()? */
	if (!himport_r(ctx->htab, NULL, 0, 0, 0, 0, 0, NULL)) {
		debug("%s: Creating entry tables failed (ret=%d)\n", __func__,
		      errno);
		return errno;
	}

	env_set_ready(ctx);

	return 0;
}

U_BOOT_ENV_CONTEXT(efi_volatile) = {
	.name = "efi_volatile",
	.htab = &efi_volatile_htab,
	.env_size = 0,
	.init = env_ctx_init_efi_volatile,
};
