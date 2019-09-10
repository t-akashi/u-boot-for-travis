// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2000-2010
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * (C) Copyright 2001 Sysgo Real-Time Solutions, GmbH <www.elinos.com>
 * Andreas Heppel <aheppel@sysgo.de>
 */

/* #define DEBUG */

#include <common.h>
#include <command.h>
#include <env.h>
#include <env_internal.h>
#include <linux/stddef.h>
#include <malloc.h>
#include <search.h>
#include <errno.h>

DECLARE_GLOBAL_DATA_PTR;

#ifndef CONFIG_SPL_BUILD
# if defined(CONFIG_CMD_SAVEENV) && defined(CONFIG_CMD_FLASH)
#  define CMD_SAVEENV
# elif defined(CONFIG_ENV_ADDR_REDUND)
#  error CONFIG_ENV_ADDR_REDUND must have CONFIG_CMD_SAVEENV & CONFIG_CMD_FLASH
# endif
#endif

#if defined(CONFIG_ENV_SIZE_REDUND) &&	\
	(CONFIG_ENV_SIZE_REDUND < CONFIG_ENV_SIZE)
#error CONFIG_ENV_SIZE_REDUND should not be less then CONFIG_ENV_SIZE
#endif

/* TODO(sjg@chromium.org): Figure out all these special cases */
#if (!defined(CONFIG_MICROBLAZE) && !defined(CONFIG_ARCH_ZYNQ) && \
	!defined(CONFIG_TARGET_MCCMON6) && !defined(CONFIG_TARGET_X600) && \
	!defined(CONFIG_TARGET_EDMINIV2)) || \
	!defined(CONFIG_SPL_BUILD)
#define LOADENV
#endif

#if !defined(CONFIG_TARGET_X600) || !defined(CONFIG_SPL_BUILD)
#define INITENV
#endif

struct env_flash_context {
	struct environment_hdr *env_ptr;
	struct environment_hdr *flash_addr;
	ulong end_addr;
	struct environment_hdr *flash_addr_new;
	ulong end_addr_new;
	ulong default_env_addr;
};

int env_flash_init_params(struct env_context *ctx,
			  struct environment_hdr *env_ptr,
			  struct environment_hdr *flash_addr, ulong end_addr,
			  struct environment_hdr *flash_addr_new,
			  ulong end_addr_new, ulong default_env_addr)
{
	struct env_flash_context *params;

	params = calloc(sizeof(*params), 1);
	if (!params)
		return -1;

	params->env_ptr = env_ptr;
	params->flash_addr = flash_addr;
	params->end_addr = end_addr;
	params->flash_addr_new = flash_addr_new;
	params->end_addr_new = end_addr_new;
	params->default_env_addr = default_env_addr;
#if 1 /* FIXME: cause hang-up */
	ctx->drv_params[ENVL_FLASH] = NULL;
#else
	ctx->drv_params[ENVL_FLASH] = params;
#endif

	return 0;
}

#ifdef CONFIG_ENV_ADDR_REDUND
#ifdef INITENV
static int env_flash_init(struct env_context *ctx)
{
	struct env_flash_context *params;
	int crc1_ok = 0, crc2_ok = 0;

	if (ctx->drv_init)
		if (ctx->drv_init(ctx, ENVL_FLASH))
			return -ENOENT;

	params = ctx->drv_params[ENVL_FLASH];
	if (!params)
		return -ENODEV;

	uchar flag1 = params->flash_addr->flags;
	uchar flag2 = params->flash_addr_new->flags;

	ulong addr_default = params->default_env_addr;
	ulong addr1 = (ulong)&params->flash_addr->data;
	ulong addr2 = (ulong)&params->flash_addr_new->data;

	crc1_ok = crc32(0, params->flash_addr->data, ctx->env_size)
			== params->flash_addr->crc;
	crc2_ok = crc32(0, params->flash_addr_new->data, ctx->env_size)
			== params->flash_addr_new->crc;

	if (crc1_ok && !crc2_ok) {
		env_set_env_addr(ctx, addr1);
		env_set_valid(ctx, ENV_VALID);
	} else if (!crc1_ok && crc2_ok) {
		env_set_env_addr(ctx, addr2);
		env_set_valid(ctx, ENV_VALID);
	} else if (!crc1_ok && !crc2_ok) {
		env_set_env_addr(ctx, addr_default);
		env_set_valid(ctx, ENV_INVALID);
	} else if (flag1 == ENV_REDUND_ACTIVE &&
		   flag2 == ENV_REDUND_OBSOLETE) {
		env_set_env_addr(ctx, addr1);
		env_set_valid(ctx, ENV_VALID);
	} else if (flag1 == ENV_REDUND_OBSOLETE &&
		   flag2 == ENV_REDUND_ACTIVE) {
		env_set_env_addr(ctx, addr2);
		env_set_valid(ctx, ENV_VALID);
	} else if (flag1 == flag2) {
		env_set_env_addr(ctx, addr1);
		env_set_valid(ctx, ENV_REDUND);
	} else if (flag1 == 0xFF) {
		env_set_env_addr(ctx, addr1);
		env_set_valid(ctx, ENV_REDUND);
	} else if (flag2 == 0xFF) {
		env_set_env_addr(ctx, addr2);
		env_set_valid(ctx, ENV_REDUND);
	}

	return 0;
}
#endif

#ifdef CMD_SAVEENV
static int env_flash_save(struct env_context *ctx)
{
	struct env_flash_context *params = ctx->drv_params[ENVL_FLASH];
	struct environment_hdr *env_new = NULL;
	size_t	env_size;
	char	*saved_data = NULL;
	char	flag = ENV_REDUND_OBSOLETE, new_flag = ENV_REDUND_ACTIVE;
	int	rc = 1;
	ulong	up_data = 0;

	debug("Protect off %08lX ... %08lX\n", (ulong)params->flash_addr,
	      params->end_addr);

	if (!params)
		return 1;

	env_size = sizeof(*env_new) + ctx->env_size;
	env_new = malloc(env_size);
	if (!env_new)
		return 1;

	if (flash_sect_protect(0, (ulong)params->flash_addr, params->end_addr))
		goto done;

	debug("Protect off %08lX ... %08lX\n",
		(ulong)params->flash_addr_new, params->end_addr_new);

	if (flash_sect_protect(0, (ulong)params->flash_addr_new,
			       params->end_addr_new))
		goto done;

	rc = env_export(ctx, env_new);
	if (rc)
		goto done;
	env_new->flags	= new_flag;

	if (env_size < CONFIG_ENV_SECT_SIZE) {
		up_data = params->end_addr_new + 1
				- ((long)params->flash_addr_new + env_size);
		debug("Data to save 0x%lX\n", up_data);
		if (up_data) {
			saved_data = malloc(up_data);
			if (!saved_data) {
				printf("Unable to save the rest of sector (%ld)\n",
				       up_data);
				goto done;
			}
			memcpy(saved_data,
			       (void *)
			       ((long)params->flash_addr_new + env_size),
			       up_data);
			debug("Data (start 0x%lX, len 0x%lX) saved at 0x%p\n",
			      (long)params->flash_addr_new + env_size,
			      up_data, saved_data);
		}
	}

	puts("Erasing Flash...");
	debug(" %08lX ... %08lX ...", (ulong)params->flash_addr_new,
	      params->end_addr_new);

	if (flash_sect_erase((ulong)params->flash_addr_new,
			     params->end_addr_new))
		goto done;

	puts("Writing to Flash... ");
	debug(" %08lX ... %08lX ...",
	      (ulong)&params->flash_addr_new->data,
	      ctx->env_size + (ulong)&params->flash_addr_new->data);
	rc = flash_write((char *)env_new, (ulong)params->flash_addr_new,
			 sizeof(*env_new) + ctx->env_size);
	if (rc)
		goto perror;

	rc = flash_write(&flag, (ulong)&params->flash_addr->flags,
			 sizeof(params->flash_addr->flags));
	if (rc)
		goto perror;

	if (env_size < CONFIG_ENV_SECT_SIZE) {
		if (up_data) { /* restore the rest of sector */
			debug("Restoring the rest of data to 0x%lX len 0x%lX\n",
			      (long)params->flash_addr_new + env_size, up_data);
			if (flash_write(saved_data,
					(long)params->flash_addr_new + env_size,
					up_data))
				goto perror;
		}
	}

	puts("done\n");

	{
		struct environment_hdr *etmp = params->flash_addr;
		ulong ltmp = params->end_addr;

		params->flash_addr = params->flash_addr_new;
		params->flash_addr_new = etmp;

		params->end_addr = params->end_addr_new;
		params->end_addr_new = ltmp;
	}

	rc = 0;
	goto done;
perror:
	flash_perror(rc);
done:
	if (saved_data)
		free(saved_data);
	/* try to re-protect */
	flash_sect_protect(1, (ulong)params->flash_addr, params->end_addr);
	flash_sect_protect(1, (ulong)params->flash_addr_new,
			   params->end_addr_new);

	free(env_new);

	return rc;
}
#endif /* CMD_SAVEENV */

#else /* ! CONFIG_ENV_ADDR_REDUND */

#ifdef INITENV
static int env_flash_init(struct env_context *ctx)
{
	struct env_flash_context *params;

	if (ctx->drv_init)
		if (ctx->drv_init(ctx, ENVL_FLASH))
			return -ENOENT;

	params = ctx->drv_params[ENVL_FLASH];
	if (!params)
		return -ENODEV;

	if (crc32(0, params->env_ptr->data, ctx->env_size)
	    == params->env_ptr->crc) {
		env_set_env_addr(ctx, (ulong)&params->env_ptr->data);
		env_set_valid(ctx, ENV_VALID);

		return 0;
	}

	env_set_env_addr(ctx, params->default_env_addr);
	env_set_valid(ctx, ENV_INVALID);

	return 0;
}
#endif

#ifdef CMD_SAVEENV
static int env_flash_save(struct env_context *ctx)
{
	struct env_flash_context *params = ctx->drv_params[ENVL_FLASH];
	struct environment_hdr *env_new;
	int	rc = 1;
	char	*saved_data = NULL;
	ulong	up_data = 0;
	size_t	env_size;

	if (!params)
		return 1;

	env_size = sizeof(*env_new) + ctx->env_size;
	env_new = malloc(env_size);
	if (!env_new)
		return 1;

	if (env_size < CONFIG_ENV_SECT_SIZE) {
		up_data = params->end_addr + 1
				- ((long)params->flash_addr + env_size);
		debug("Data to save 0x%lx\n", up_data);
		if (up_data) {
			saved_data = malloc(up_data);
			if (!saved_data) {
				printf("Unable to save the rest of sector (%ld)\n",
				       up_data);
				goto done;
			}
			memcpy(saved_data,
			       (void *)((long)params->flash_addr + env_size),
			       up_data);
			debug("Data (start 0x%lx, len 0x%lx) saved at 0x%lx\n",
			      (ulong)params->flash_addr + env_size,
			      up_data,
			      (ulong)saved_data);
		}
	}

	debug("Protect off %08lX ... %08lX\n", (ulong)params->flash_addr,
	      params->end_addr);

	if (flash_sect_protect(0, (long)params->flash_addr, params->end_addr))
		goto done;

	rc = env_export(ctx, env_new);
	if (rc)
		goto done;

	puts("Erasing Flash...");
	if (flash_sect_erase((long)params->flash_addr, params->end_addr))
		goto done;

	puts("Writing to Flash... ");
	rc = flash_write((char *)env_new, (long)params->flash_addr, env_size);
	if (rc != 0)
		goto perror;

	if ((env_size < CONFIG_ENV_SECT_SIZE) && up_data) {
		/* restore the rest of sector */
		debug("Restoring the rest of data to 0x%lx len 0x%lx\n",
			(ulong)params->flash_addr + env_size, up_data);
		if (flash_write(saved_data, (long)params->flash_addr + env_size,
				up_data))
			goto perror;
	}

	puts("done\n");
	rc = 0;
	goto done;
perror:
	flash_perror(rc);
done:
	if (saved_data)
		free(saved_data);
	/* try to re-protect */
	flash_sect_protect(1, (long)params->flash_addr, params->end_addr);
	free(env_new);

	return rc;
}
#endif /* CMD_SAVEENV */

#endif /* CONFIG_ENV_ADDR_REDUND */

#ifdef LOADENV
static int env_flash_load(struct env_context *ctx)
{
	struct env_flash_context *params = ctx->drv_params[ENVL_FLASH];

	if (!params)
		return -ENODEV;

#ifdef CONFIG_ENV_ADDR_REDUND
	if (env_get_env_addr(ctx) != (ulong)&params->flash_addr->data) {
		struct environment_hdr *etmp = params->flash_addr;
		ulong ltmp = params->end_addr;

		params->flash_addr = params->flash_addr_new;
		params->flash_addr_new = etmp;

		params->end_addr = params->end_addr_new;
		params->end_addr_new = ltmp;
	}

	if (params->flash_addr_new->flags != ENV_REDUND_OBSOLETE &&
	    crc32(0, params->flash_addr_new->data, ctx->env_size)
			== params->flash_addr_new->crc) {
		char flag = ENV_REDUND_OBSOLETE;

		env_set_valid(ctx, ENV_REDUND);
		flash_sect_protect(0, (ulong)params->flash_addr_new,
				   params->end_addr_new);
		flash_write(&flag,
			    (ulong)&params->flash_addr_new->flags,
			    sizeof(params->flash_addr_new->flags));
		flash_sect_protect(1, (ulong)params->flash_addr_new,
				   params->end_addr_new);
	}

	if (params->flash_addr->flags != ENV_REDUND_ACTIVE &&
	    (params->flash_addr->flags & ENV_REDUND_ACTIVE)
			== ENV_REDUND_ACTIVE) {
		char flag = ENV_REDUND_ACTIVE;

		env_set_valid(ctx, ENV_REDUND);
		flash_sect_protect(0, (ulong)params->flash_addr,
				   params->end_addr);
		flash_write(&flag,
			    (ulong)&params->flash_addr->flags,
			    sizeof(params->flash_addr->flags));
		flash_sect_protect(1, (ulong)params->flash_addr,
				   params->end_addr);
	}

	if (env_get_valid(ctx) == ENV_REDUND)
		puts("*** Warning - some problems detected "
		     "reading environment; recovered successfully\n\n");
#endif /* CONFIG_ENV_ADDR_REDUND */

	return env_import(ctx, (char *)params->flash_addr, 1);
}
#endif /* LOADENV */

U_BOOT_ENV_LOCATION(flash) = {
	.location	= ENVL_FLASH,
	ENV_NAME("Flash")
#ifdef LOADENV
	.load		= env_flash_load,
#endif
#ifdef CMD_SAVEENV
	.save		= env_save_ptr(env_flash_save),
#endif
#ifdef INITENV
	.init		= env_flash_init,
#endif
};
