// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 Linaro Limited
 *		Author: AKASHI Takahiro
 */

#include <common.h>
#include <env_default.h>
#include <env_flags.h>
#include <env_internal.h>
#include <search.h>

DECLARE_GLOBAL_DATA_PTR;

#if !defined(ENV_IS_IN_DEVICE) && !defined(CONFIG_ENV_IS_NOWHERE)
# error Define one of CONFIG_ENV_IS_IN_{EEPROM|FLASH|MMC|FAT|EXT4|\
NAND|NVRAM|ONENAND|SATA|SPI_FLASH|REMOTE|UBI} or CONFIG_ENV_IS_NOWHERE
#endif

struct hsearch_data env_htab = {
#if CONFIG_IS_ENABLED(ENV_SUPPORT)
	/* defined in flags.c, only compile with ENV_SUPPORT */
	.change_ok = env_flags_validate,
#endif
};

/*
 * NOTE: extracted from env/env.c
 */
static bool env_has_inited_uboot(struct env_context *ctx,
				 enum env_location location)
{
	return gd->env_has_init & BIT(location);
}

static void env_set_inited_uboot(struct env_context *ctx,
				 enum env_location location)
{
	gd->env_has_init |= BIT(location);
}

static int env_get_load_prio_uboot(struct env_context *ctx)
{
	return gd->env_load_prio;
}

static enum env_location env_get_location_uboot(struct env_context *ctx,
						enum env_operation op, int prio)
{
	gd->env_load_prio = prio;

	return env_locations[prio];
}

int env_get_char_default_uboot(struct env_context *ctx, int index)
{
	return default_environment[index];
}

int env_get_char_spec_uboot(struct env_context *ctx, int index)
{
	return *(uchar *)(gd->env_addr + index);
}

static int env_init_uboot(struct env_context *ctx)
{
	struct env_driver *drv;
	int ret = -ENOENT;
	int prio;

	for (prio = 0; (drv = env_driver_lookup(ctx, ENVOP_INIT, prio));
	     prio++) {
		if (!drv->init || !(ret = drv->init(ctx)))
			gd->env_has_init |= BIT(drv->location);

		debug("%s: Environment %s init done (ret=%d)\n", __func__,
		      drv->name, ret);
	}

	if (!prio)
		return -ENODEV;

	if (ret == -ENOENT) {
		gd->env_addr = (ulong)&default_environment[0];
		gd->env_valid = ENV_VALID;

		return 0;
	}

	return ret;
}

static int env_drv_init_uboot(struct env_context *ctx, enum env_location loc)
{
	__maybe_unused int ret;

	switch (loc) {
#ifdef CONFIG_ENV_IS_IN_FLASH
	case ENVL_FLASH: {
		struct environment_hdr *env_ptr;
		struct environment_hdr *flash_addr;
		ulong end_addr;
		struct environment_hdr *flash_addr_new;
		ulong end_addr_new;

#ifdef ENV_IS_EMBEDDED
		env_ptr = &embedded_environment;
#else /* ! ENV_IS_EMBEDDED */
		env_ptr = (struct environment_hdr *)CONFIG_ENV_ADDR;
#endif /* ENV_IS_EMBEDDED */
		flash_addr = (struct environment_hdr *)CONFIG_ENV_ADDR;

/* CONFIG_ENV_ADDR is supposed to be on sector boundary */
		end_addr = CONFIG_ENV_ADDR + CONFIG_ENV_SECT_SIZE - 1;

#ifdef CONFIG_ENV_ADDR_REDUND
		flash_addr_new =
			(struct environment_hdr *)CONFIG_ENV_ADDR_REDUND;
/* CONFIG_ENV_ADDR_REDUND is supposed to be on sector boundary */
		end_addr_new = CONFIG_ENV_ADDR_REDUND
					+ CONFIG_ENV_SECT_SIZE - 1;
#else
		flash_addr_new = NULL;
		end_addr_new = 0;
#endif /* CONFIG_ENV_ADDR_REDUND */

		ret = env_flash_init_params(ctx, env_ptr, flash_addr, end_addr,
					    flash_addr_new, end_addr_new,
					    (ulong)&default_environment[0]);
		if (ret)
			return -ENOENT;

		return 0;
		}
#endif
#ifdef CONFIG_ENV_IS_IN_FAT
	case ENVL_FAT: {
		ret = env_fat_init_params(ctx,
					  CONFIG_ENV_FAT_INTERFACE,
					  CONFIG_ENV_FAT_DEVICE_AND_PART,
					  CONFIG_ENV_FAT_FILE);

		return -ENOENT;
		}
#endif
#ifdef CONFIG_ENV_DRV_NONE
	case ENVL_NOWHERE:
#ifdef CONFIG_ENV_IS_NOWHERE
		gd->env_addr = (ulong)&default_environment[0];
		gd->env_valid = ENV_INVALID;

		return 0;
#else
		return -ENOENT;
#endif
#endif
	default:
		return -ENOENT;
	}
}

/*
 * NOTE: extracted from env/common.c
 */
void env_set_ready_uboot(struct env_context *ctx)
{
	gd->flags |= GD_FLG_ENV_READY;
}

bool env_is_ready_uboot(struct env_context *ctx)
{
	return (gd->flags & GD_FLG_ENV_READY);
}

void env_set_valid_uboot(struct env_context *ctx, enum env_valid valid)
{
	gd->env_valid = valid;
}

enum env_valid env_get_valid_uboot(struct env_context *ctx)
{
	return gd->env_valid;
}

void env_set_addr_uboot(struct env_context *ctx, ulong env_addr)
{
	gd->env_addr = env_addr;
}

ulong env_get_addr_uboot(struct env_context *ctx)
{
	return gd->env_addr;
}

/*
 * Look up the variable from the default environment
 */
char *env_get_default_uboot(struct env_context *ctx, const char *name)
{
	char *ret_val;
	unsigned long really_valid = gd->env_valid;
	unsigned long real_gd_flags = gd->flags;

	/* Pretend that the image is bad. */
	gd->flags &= ~GD_FLG_ENV_READY;
	gd->env_valid = ENV_INVALID;
	ret_val = env_get(ctx, name);
	gd->env_valid = really_valid;
	gd->flags = real_gd_flags;
	return ret_val;
}

void env_set_default_env_uboot(struct env_context *ctx, const char *s,
			       int flags)
{
	if (sizeof(default_environment) > ctx->env_size) {
		puts("*** Error - default environment is too large\n\n");
		return;
	}

	if (s) {
		if ((flags & H_INTERACTIVE) == 0)
			printf("*** Warning - %s, using default environment\n\n", s);
		else
			puts(s);
	} else {
		debug("Using default environment\n");
	}

	env_htab.ctx = ctx;
	if (himport_r(&env_htab, (char *)default_environment,
		      sizeof(default_environment), '\0', flags, 0,
		      0, NULL) == 0)
		pr_err("## Error: Environment import failed: errno = %d\n",
		       errno);

	gd->flags |= GD_FLG_ENV_READY;
	gd->flags |= GD_FLG_ENV_DEFAULT;
}

/* [re]set individual variables to their value in the default environment */
int env_set_default_vars_uboot(struct env_context *ctx, int nvars,
			       char * const vars[], int flags)
{
	/*
	 * Special use-case: import from default environment
	 * (and use \0 as a separator)
	 */
	flags |= H_NOCLEAR;
	env_htab.ctx = ctx;
	return himport_r(&env_htab, (const char *)default_environment,
				sizeof(default_environment), '\0',
				flags, 0, nvars, vars);
}

void env_post_relocate_uboot(struct env_context *ctx)
{
	if (gd->env_valid == ENV_INVALID) {
#if defined(CONFIG_ENV_IS_NOWHERE) || defined(CONFIG_SPL_BUILD)
		/* Environment not changeable */
		env_set_default(ctx, NULL, 0);
#else
		bootstage_error(BOOTSTAGE_ID_NET_CHECKSUM);
		env_set_default(ctx, "bad CRC", 0);
#endif
	} else {
		env_load(ctx);
	}
}

U_BOOT_ENV_CONTEXT(uboot) = {
	.name = "uboot",
	.htab = &env_htab,
	.env_size = ENV_SIZE,
	.has_inited = env_has_inited_uboot,
	.set_inited = env_set_inited_uboot,
	.get_load_prio = env_get_load_prio_uboot,
	.get_location = env_get_location_uboot,
	.get_char_default = env_get_char_default_uboot,
	.get_char_spec = env_get_char_spec_uboot,
	.init = env_init_uboot,
	.drv_init = env_drv_init_uboot,
	.get_default = env_get_default_uboot,
	.set_default = env_set_default_env_uboot,
	.set_default_vars = env_set_default_vars_uboot,
	.set_ready = env_set_ready_uboot,
	.is_ready = env_is_ready_uboot,
	.set_valid = env_set_valid_uboot,
	.get_valid = env_get_valid_uboot,
	.set_addr = env_set_addr_uboot,
	.get_addr = env_get_addr_uboot,
	.post_relocate = env_post_relocate_uboot,
};
