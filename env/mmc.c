// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2008-2011 Freescale Semiconductor, Inc.
 */

/* #define DEBUG */

#include <common.h>

#include <command.h>
#include <env.h>
#include <env_internal.h>
#include <fdtdec.h>
#include <linux/stddef.h>
#include <malloc.h>
#include <memalign.h>
#include <mmc.h>
#include <part.h>
#include <search.h>
#include <errno.h>

DECLARE_GLOBAL_DATA_PTR;

struct env_mmc_context {
	int dev;
	int part;
	s64 offset;
	s64 offset_redund;
};

int env_mmc_init_params(struct env_context *ctx, int dev, int part,
			s64 offset, s64 offset_redund)
{
	struct env_mmc_context *params;

	params = calloc(sizeof(*params), 1);
	if (!params)
		return -1;

	params->dev = dev;
	params->part = part;
	params->offset = offset;
	params->offset_redund = offset_redund;

	ctx->drv_params[ENVL_MMC] = params;

	return 0;
}

static inline s64 mmc_offset(struct env_context *ctx, int copy)
{
	struct env_mmc_context *params = ctx->drv_params[ENVL_MMC];
	s64 offset = CONFIG_ENV_OFFSET;

	offset = params->offset;
	if (params->offset_redund && copy)
		offset = params->offset_redund;

	return offset;
}

__weak int mmc_get_env_addr(struct env_context *ctx, struct mmc *mmc, int copy,
			    u32 *env_addr)
{
	s64 offset = mmc_offset(ctx, copy);

	if (offset < 0)
		offset += mmc->capacity;

	*env_addr = offset;

	return 0;
}

__weak int mmc_get_env_dev(struct env_context *ctx)
{
	struct env_mmc_context *params;

	params = ctx->drv_params[ENVL_MMC];
	if (!params)
		return -ENODEV;

	return params->dev;
}

__weak uint mmc_get_env_part(struct env_context *ctx, struct mmc *mmc)
{
	struct env_mmc_context *params;

	params = ctx->drv_params[ENVL_MMC];
	if (!params)
		return -ENODEV;

	return params->part;
}

static unsigned char env_mmc_orig_hwpart;

static int mmc_set_env_part(struct env_context *ctx, struct mmc *mmc)
{
	struct env_mmc_context *params = ctx->drv_params[ENVL_MMC];
	uint part = mmc_get_env_part(ctx, mmc);
	int dev = mmc_get_env_dev(ctx);
	int ret = 0;

	if (params->part) {
		env_mmc_orig_hwpart = mmc_get_blk_desc(mmc)->hwpart;
		ret = blk_select_hwpart_devnum(IF_TYPE_MMC, dev, part);
		if (ret)
			puts("MMC partition switch failed\n");

		return ret;
	}

	return 0;
}

static const char *init_mmc_for_env(struct env_context *ctx, struct mmc *mmc)
{
	if (!mmc)
		return "No MMC card found";

#if CONFIG_IS_ENABLED(BLK)
	struct udevice *dev;

	if (blk_get_from_parent(mmc->dev, &dev))
		return "No block device";
#else
	if (mmc_init(mmc))
		return "MMC init failed";
#endif
	if (mmc_set_env_part(ctx, mmc))
		return "MMC partition switch failed";

	return NULL;
}

static void fini_mmc_for_env(struct env_context *ctx, struct mmc *mmc)
{
	struct env_mmc_context *params = ctx->drv_params[ENVL_MMC];

	if (params->part) {
		int dev = mmc_get_env_dev(ctx);

		blk_select_hwpart_devnum(IF_TYPE_MMC, dev, env_mmc_orig_hwpart);
	}
}

#if defined(CONFIG_CMD_SAVEENV) && !defined(CONFIG_SPL_BUILD)
static inline int write_env(struct mmc *mmc, unsigned long size,
			    unsigned long offset, const void *buffer)
{
	uint blk_start, blk_cnt, n;
	struct blk_desc *desc = mmc_get_blk_desc(mmc);

	blk_start	= ALIGN(offset, mmc->write_bl_len) / mmc->write_bl_len;
	blk_cnt		= ALIGN(size, mmc->write_bl_len) / mmc->write_bl_len;

	n = blk_dwrite(desc, blk_start, blk_cnt, (u_char *)buffer);

	return (n == blk_cnt) ? 0 : -1;
}

static int env_mmc_save(struct env_context *ctx)
{
	struct env_mmc_context *params;
	struct environment_hdr *env_new;
	size_t env_size;
	int dev = mmc_get_env_dev(ctx);
	struct mmc *mmc = find_mmc_device(dev);
	u32	offset;
	int	ret, copy = 0;
	const char *errmsg;

	params = ctx->drv_params[ENVL_MMC];
	if (!params)
		return 1;

	env_size = sizeof(*env_new) * ctx->env_size;
	env_new = malloc(env_size);
	if (!env_new)
		return 1;

	errmsg = init_mmc_for_env(ctx, mmc);
	if (errmsg) {
		printf("%s\n", errmsg);
		return 1;
	}

	ret = env_export(ctx, env_new);
	if (ret)
		goto fini;

	if (params->offset_redund && env_get_valid(ctx) == ENV_VALID)
		copy = 1;

	if (mmc_get_env_addr(ctx, mmc, copy, &offset)) {
		ret = 1;
		goto fini;
	}

	printf("Writing to %sMMC(%d)... ", copy ? "redundant " : "", dev);
	if (write_env(mmc, env_size, offset, (u_char *)env_new)) {
		puts("failed\n");
		ret = 1;
		goto fini;
	}

	ret = 0;

	if (params->offset_redund)
		env_set_valid(ctx, env_get_valid(ctx) == ENV_REDUND ?
					ENV_VALID : ENV_REDUND);

fini:
	fini_mmc_for_env(ctx, mmc);
	return ret;
}

#if defined(CONFIG_CMD_ERASEENV)
static inline int erase_env(struct mmc *mmc, unsigned long size,
			    unsigned long offset)
{
	uint blk_start, blk_cnt, n;
	struct blk_desc *desc = mmc_get_blk_desc(mmc);

	blk_start	= ALIGN(offset, mmc->write_bl_len) / mmc->write_bl_len;
	blk_cnt		= ALIGN(size, mmc->write_bl_len) / mmc->write_bl_len;

	n = blk_derase(desc, blk_start, blk_cnt);
	printf("%d blocks erased: %s\n", n, (n == blk_cnt) ? "OK" : "ERROR");

	return (n == blk_cnt) ? 0 : 1;
}

static int env_mmc_erase(struct env_context *ctx)
{
	struct env_mmc_context *params;
	int dev = mmc_get_env_dev(ctx);
	struct mmc *mmc = find_mmc_device(dev);
	int	ret, copy = 0;
	u32	offset;
	const char *errmsg;
	size_t env_size;

	params = ctx->drv_params[ENVL_MMC];
	if (!params)
		return 1;

	errmsg = init_mmc_for_env(ctx, mmc);
	if (errmsg) {
		printf("%s\n", errmsg);
		return 1;
	}

	if (mmc_get_env_addr(ctx, mmc, copy, &offset))
		return CMD_RET_FAILURE;

	env_size = sizeof(struct environment_hdr) + ctx->env_size;
	ret = erase_env(mmc, env_size, offset);

	if (params->offset_redund) {
		copy = 1;

		if (mmc_get_env_addr(ctx, mmc, copy, &offset))
			return CMD_RET_FAILURE;

		ret |= erase_env(mmc, env_size, offset);
	}

	return ret;
}
#endif /* CONFIG_CMD_ERASEENV */
#endif /* CONFIG_CMD_SAVEENV && !CONFIG_SPL_BUILD */

static inline int read_env(struct mmc *mmc, unsigned long size,
			   unsigned long offset, const void *buffer)
{
	uint blk_start, blk_cnt, n;
	struct blk_desc *desc = mmc_get_blk_desc(mmc);

	blk_start	= ALIGN(offset, mmc->read_bl_len) / mmc->read_bl_len;
	blk_cnt		= ALIGN(size, mmc->read_bl_len) / mmc->read_bl_len;

	n = blk_dread(desc, blk_start, blk_cnt, (uchar *)buffer);

	return (n == blk_cnt) ? 0 : -1;
}

static int env_mmc_load(struct env_context *ctx)
{
#if defined(ENV_IS_EMBEDDED)
	return 0;
#endif
	struct env_mmc_context *params;
	size_t env_size;
	int dev = mmc_get_env_dev(ctx);
	struct mmc *mmc;
	const char *errmsg = NULL;
	int ret = 0;

	params = ctx->drv_params[ENVL_MMC];
	if (!params)
		return 1;

#ifdef CONFIG_ENV_OFFSET_REDUND
	struct environment_hdr *tmp_env1, *tmp_env2;
	u32 offset1, offset2;
	int read1_fail = 0, read2_fail = 0;

	env_size = sizeof(*tmp_env1) + ctx->env_size;
	tmp_env1 = malloc(env_size);
	if (!tmp_env1) {
		ret = -ENOMEM;
		goto err;
	}
	tmp_env2 = malloc(env_size);
	if (!tmp_env2) {
		free(tmp_env1);
		ret = -ENOMEM;
		goto err;
	}

	mmc_initialize(NULL);

	mmc = find_mmc_device(dev);

	errmsg = init_mmc_for_env(ctx, mmc);
	if (errmsg) {
		ret = -EIO;
		goto err;
	}

	if (mmc_get_env_addr(ctx, mmc, 0, &offset1) ||
	    mmc_get_env_addr(ctx, mmc, 1, &offset2)) {
		ret = -EIO;
		goto fini;
	}

	read1_fail = read_env(mmc, env_size, offset1, tmp_env1);
	read2_fail = read_env(mmc, env_size, offset2, tmp_env2);

	ret = env_import_redund(ctx, (char *)tmp_env1, read1_fail,
				(char *)tmp_env2, read2_fail);

fini:
	fini_mmc_for_env(ctx, mmc);
err:
	if (ret)
		env_set_default(ctx, errmsg, 0);

#else /* ! CONFIG_ENV_OFFSET_REDUND */
	char * buf;
	u32 offset;

	env_size = sizeof(struct environment_hdr) + ctx->env_size;
	buf = malloc(env_size);
	if (!buf) {
		ret = -ENOMEM;
		goto err;
	}

	mmc = find_mmc_device(dev);

	errmsg = init_mmc_for_env(ctx, mmc);
	if (errmsg) {
		ret = -EIO;
		goto err;
	}

	if (mmc_get_env_addr(ctx, mmc, 0, &offset)) {
		ret = -EIO;
		goto fini;
	}

	if (read_env(mmc, env_size, offset, buf)) {
		errmsg = "!read failed";
		ret = -EIO;
		goto fini;
	}

	ret = env_import(ctx, buf, 1);

fini:
	fini_mmc_for_env(ctx, mmc);
err:
	if (ret)
		env_set_default(ctx, errmsg, 0);
#endif /* CONFIG_ENV_OFFSET_REDUND */

	return ret;
}

U_BOOT_ENV_LOCATION(mmc) = {
	.location	= ENVL_MMC,
	ENV_NAME("MMC")
	.load		= env_mmc_load,
#ifndef CONFIG_SPL_BUILD
	.save		= env_save_ptr(env_mmc_save),
#if defined(CONFIG_CMD_ERASEENV)
	.erase		= env_mmc_erase,
#endif
#endif
};
