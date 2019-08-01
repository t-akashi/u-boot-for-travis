// SPDX-License-Identifier: GPL-2.0+
/*
 * (c) Copyright 2011 by Tigris Elektronik GmbH
 *
 * Author:
 *  Maximilian Schwerin <mvs@tigris.de>
 */

#include <common.h>

#include <command.h>
#include <env.h>
#include <env_internal.h>
#include <linux/stddef.h>
#include <malloc.h>
#include <memalign.h>
#include <search.h>
#include <errno.h>
#include <fat.h>
#include <mmc.h>

#ifdef CONFIG_SPL_BUILD
/* TODO(sjg@chromium.org): Figure out why this is needed */
# if !defined(CONFIG_TARGET_AM335X_EVM) || defined(CONFIG_SPL_OS_BOOT)
#  define LOADENV
# endif
#else
# define LOADENV
# if defined(CONFIG_CMD_SAVEENV)
#  define CMD_SAVEENV
# endif
#endif

struct env_fat_context {
	const char *interface;
	const char *dev_and_part;
	const char *file;
};

int env_fat_init_params(struct env_context *ctx, const char *interface,
			const char *dev_part, const char *file)
{
	struct env_fat_context *params;

	params = calloc(sizeof(*params), 1);
	if (!params)
		return -1;

	params->interface = interface;
	params->dev_and_part = dev_part;
	params->file = file;
	ctx->drv_params[ENVL_FAT] = params;

	return 0;
}

#ifdef CMD_SAVEENV
static int env_fat_save(struct env_context *ctx)
{
	env_hdr_t *env_new;
	struct blk_desc *dev_desc = NULL;
	disk_partition_t info;
	int dev, part;
	struct env_fat_context *params = ctx->drv_params[ENVL_FAT];
	int err;
	loff_t size;

	if (!params)
		return 1;

	env_new = malloc_cache_aligned(sizeof(env_hdr_t) + ctx->env_size);
	if (!env_new)
		return 1;

	err = env_export(ctx, env_new);
	if (err)
		goto out;
	err = 1;

	part = blk_get_device_part_str(params->interface,
				       params->dev_and_part,
				       &dev_desc, &info, 1);
	if (part < 0)
		goto out;

	dev = dev_desc->devnum;
	if (fat_set_blk_dev(dev_desc, &info) != 0) {
		/*
		 * This printf is embedded in the messages from env_save that
		 * will calling it. The missing \n is intentional.
		 */
		printf("Unable to use %s %d:%d... ",
		       params->interface, dev, part);
		goto out;
	}

	err = file_fat_write(params->file, (void *)env_new, 0,
			     sizeof(env_hdr_t) + ctx->env_size, &size);
	if (err == -1) {
		/*
		 * This printf is embedded in the messages from env_save that
		 * will calling it. The missing \n is intentional.
		 */
		printf("Unable to write \"%s\" from %s%d:%d... ",
			params->file, params->interface, dev, part);
		err = 1;
		goto out;
	}
	err = 0;
out:
	free(env_new);

	return err;
}
#endif /* CMD_SAVEENV */

#ifdef LOADENV
static int env_fat_load(struct env_context *ctx)
{
	struct env_fat_context *params = ctx->drv_params[ENVL_FAT];
	ALLOC_CACHE_ALIGN_BUFFER(char, buf, sizeof(env_hdr_t) + ctx->env_size);
	struct blk_desc *dev_desc = NULL;
	disk_partition_t info;
	int dev, part;
	int err;

	if (!params)
		return -ENODEV;

#ifdef CONFIG_MMC
	if (!strcmp(params->interface, "mmc"))
		mmc_initialize(NULL);
#endif

	part = blk_get_device_part_str(params->interface,
				       params->dev_and_part,
				       &dev_desc, &info, 1);
	if (part < 0)
		goto err_env_relocate;

	dev = dev_desc->devnum;
	if (fat_set_blk_dev(dev_desc, &info) != 0) {
		/*
		 * This printf is embedded in the messages from env_save that
		 * will calling it. The missing \n is intentional.
		 */
		printf("Unable to use %s %d:%d... ",
		       params->interface, dev, part);
		goto err_env_relocate;
	}

	err = file_fat_read(params->file, buf,
			    sizeof(env_hdr_t) + ctx->env_size);
	if (err == -1) {
		/*
		 * This printf is embedded in the messages from env_save that
		 * will calling it. The missing \n is intentional.
		 */
		printf("Unable to read \"%s\" from %s%d:%d... ",
			params->file, params->interface, dev, part);
		goto err_env_relocate;
	}

	return env_import(ctx, buf, 1);

err_env_relocate:
	env_set_default(ctx, NULL, 0);

	return -EIO;
}
#endif /* LOADENV */

static int env_fat_init(struct env_context *ctx)
{
	if (ctx->drv_init)
		return ctx->drv_init(ctx, ENVL_FAT);

	return -ENOENT;
}

U_BOOT_ENV_LOCATION(fat) = {
	.location	= ENVL_FAT,
	ENV_NAME("FAT")
#ifdef LOADENV
	.load		= env_fat_load,
#endif
#ifdef CMD_SAVEENV
	.save		= env_save_ptr(env_fat_save),
#endif
	.init		= env_fat_init,
};
