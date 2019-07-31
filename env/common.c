// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2000-2010
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * (C) Copyright 2001 Sysgo Real-Time Solutions, GmbH <www.elinos.com>
 * Andreas Heppel <aheppel@sysgo.de>
 */

#include <common.h>
#include <command.h>
#include <env.h>
#include <env_internal.h>
#include <linux/stddef.h>
#include <search.h>
#include <errno.h>
#include <malloc.h>

DECLARE_GLOBAL_DATA_PTR;

/*
 * Read an environment variable as a boolean
 * Return -1 if variable does not exist (default to true)
 */
int env_get_yesno(const char *var)
{
	char *s = env_get(ctx_uboot, var);

	if (s == NULL)
		return -1;
	return (*s == '1' || *s == 'y' || *s == 'Y' || *s == 't' || *s == 'T') ?
		1 : 0;
}

char *env_get_default(struct env_context *ctx, const char *name)
{
	if (ctx->get_default)
		return ctx->get_default(ctx, name);

	/* no default action */
	return NULL;
}

void env_set_default(struct env_context *ctx, const char *s, int flags)
{
	if (ctx->set_default)
		return ctx->set_default(ctx, s, flags);

	/* no default action */
}

/* [re]set individual variables to their value in the default environment */
int env_set_default_vars(struct env_context *ctx, int nvars,
			 char * const vars[], int flags)
{
	if (ctx->set_default_vars)
		return ctx->set_default_vars(ctx, nvars, vars, flags);

	/* no default action */
	return 1;
}

void env_set_ready(struct env_context *ctx)
{
	if (ctx->set_ready)
		ctx->set_ready(ctx);
	else
		/* TODO: define another macro? */
		ctx->flags |= GD_FLG_ENV_READY;
}

bool env_is_ready(struct env_context *ctx)
{
	if (ctx->is_ready)
		return ctx->is_ready(ctx);

	return ctx->flags & GD_FLG_ENV_READY;
}

void env_set_valid(struct env_context *ctx, enum env_valid valid)
{
	if (ctx->set_ready)
		ctx->set_valid(ctx, valid);
	else
		ctx->valid = valid;
}

enum env_valid env_get_valid(struct env_context *ctx)
{
	if (ctx->get_valid)
		return ctx->get_valid(ctx);

	return ctx->valid;
}

void env_set_env_addr(struct env_context *ctx, ulong env_addr)
{
	if (ctx->set_addr)
		ctx->set_addr(ctx, env_addr);
}

ulong env_get_env_addr(struct env_context *ctx)
{
	if (ctx->get_addr)
		return ctx->get_addr(ctx);

	return 0; /* FIXME: invalid value */
}

/*
 * Check if CRC is valid and (if yes) import the environment.
 * Note that "buf" may or may not be aligned.
 */
int env_import(struct env_context *ctx, const char *buf, int check)
{
	struct environment_hdr *ep = (struct environment_hdr *)buf;

	if (check) {
		uint32_t crc;

		memcpy(&crc, &ep->crc, sizeof(crc));

		if (crc32(0, ep->data, ctx->env_size) != crc) {
			env_set_default(ctx, "bad CRC", 0);
			return -ENOMSG; /* needed for env_load() */
		}
	}

	ctx->htab->ctx = ctx; /* FIXME: why needed here? */
	if (himport_r(ctx->htab, (char *)ep->data, ctx->env_size, '\0', 0, 0,
		      0, NULL)) {
		env_set_ready(ctx);
		return 0;
	}

	pr_err("Cannot import environment: errno = %d\n", errno);

	env_set_default(ctx, "import failed", 0);

	return -EIO;
}

#ifdef CONFIG_SYS_REDUNDAND_ENVIRONMENT
int env_import_redund(struct env_context *ctx,
		      const char *buf1, int buf1_read_fail,
		      const char *buf2, int buf2_read_fail)
{
	int crc1_ok, crc2_ok;
	struct environment_hdr *ep, *tmp_env1, *tmp_env2;

	tmp_env1 = (struct environment_hdr *)buf1;
	tmp_env2 = (struct environment_hdr *)buf2;

	if (buf1_read_fail && buf2_read_fail) {
		puts("*** Error - No Valid Environment Area found\n");
	} else if (buf1_read_fail || buf2_read_fail) {
		puts("*** Warning - some problems detected ");
		puts("reading environment; recovered successfully\n");
	}

	if (buf1_read_fail && buf2_read_fail) {
		env_set_default(ctx, "bad env area", 0);
		return -EIO;
	} else if (!buf1_read_fail && buf2_read_fail) {
		env_set_valid(ctx, ENV_VALID);
		return env_import(ctx, (char *)tmp_env1, 1);
	} else if (buf1_read_fail && !buf2_read_fail) {
		env_set_valid(ctx, ENV_REDUND);
		return env_import(ctx, (char *)tmp_env2, 1);
	}

	crc1_ok = crc32(0, tmp_env1->data, ctx->env_size) ==
			tmp_env1->crc;
	crc2_ok = crc32(0, tmp_env2->data, ctx->env_size) ==
			tmp_env2->crc;

	if (!crc1_ok && !crc2_ok) {
		env_set_default(ctx, "bad CRC", 0);
		return -ENOMSG; /* needed for env_load() */
	} else if (crc1_ok && !crc2_ok) {
		env_set_valid(ctx, ENV_VALID);
	} else if (!crc1_ok && crc2_ok) {
		env_set_valid(ctx, ENV_REDUND);
	} else {
		/* both ok - check serial */
		if (tmp_env1->flags == 255 && tmp_env2->flags == 0)
			env_set_valid(ctx, ENV_REDUND);
		else if (tmp_env2->flags == 255 && tmp_env1->flags == 0)
			env_set_valid(ctx, ENV_VALID);
		else if (tmp_env1->flags > tmp_env2->flags)
			env_set_valid(ctx, ENV_VALID);
		else if (tmp_env2->flags > tmp_env1->flags)
			env_set_valid(ctx, ENV_REDUND);
		else /* flags are equal - almost impossible */
			env_set_valid(ctx, ENV_VALID);
	}

	if (env_get_valid(ctx) == ENV_VALID)
		ep = tmp_env1;
	else
		ep = tmp_env2;

	/* FIXME: functionize? */
	ctx->env_flags = ep->flags;
	return env_import(ctx, (char *)ep, 0);
}
#endif /* CONFIG_SYS_REDUNDAND_ENVIRONMENT */

/* Export the environment and generate CRC for it. */
int env_export(struct env_context *ctx, struct environment_hdr *env_out)
{
	char *res;
	ssize_t	len;

	res = (char *)env_out->data;
	len = hexport_r(ctx->htab, '\0', 0, &res, ctx->env_size, 0, NULL);
	if (len < 0) {
		pr_err("Cannot export environment: errno = %d\n", errno);
		return 1;
	}

	env_out->crc = crc32(0, env_out->data, ctx->env_size);

#ifdef CONFIG_SYS_REDUNDAND_ENVIRONMENT
	env_out->flags = ++ctx->env_flags; /* increase the serial */
#endif

	return 0;
}

void env_relocate(void)
{
	struct env_context *ctx;
	int i;

#if defined(CONFIG_NEEDS_MANUAL_RELOC)
	env_reloc();
	env_fix_drivers();

	for (i = 0; i < U_BOOT_ENV_CTX_COUNT; i++) {
		if (ctx->htab.change_ok)
			ctx->htab.change_ok += gd->reloc_off;

		/*
		 * TODO:
		 * Some of functions may not be called after relocation
		 */
		if (ctx->has_inited)
			ctx->has_inited += gd->reloc_off;
		if (ctx->set_inited)
			ctx->set_inited += gd->reloc_off;
		if (ctx->get_location)
			ctx->get_location += gd->reloc_off;
		if (ctx->get_char)
			ctx->get_char += gd->reloc_off;
		if (ctx->get_char_default)
			ctx->get_char_default += gd->reloc_off;
		if (ctx->get_char_spec)
			ctx->get_char_spec += gd->reloc_off;
		if (ctx->init)
			ctx->init += gd->reloc_off;
		if (ctx->get_default)
			ctx->get_default += gd->reloc_off;
		if (ctx->set_default)
			ctx->set_default += gd->reloc_off;
		if (ctx->set_default_vars)
			ctx->set_default_vars += gd->reloc_off;
		if (ctx->set_ready)
			ctx->set_ready += gd->reloc_off;
		if (ctx->set_valid)
			ctx->set_valid += gd->reloc_off;
		if (ctx->get_valid)
			ctx->get_valid += gd->reloc_off;
	}
#endif

	for (i = 0, ctx = U_BOOT_ENV_CTX_START; i < U_BOOT_ENV_CTX_COUNT;
	     i++, ctx++)
		if (ctx->post_relocate)
			ctx->post_relocate(ctx);
}

#ifdef CONFIG_AUTO_COMPLETE
/*
 * TODO: Currently U-Boot environment context only
 */
int env_complete(char *var, int maxv, char *cmdv[], int bufsz, char *buf,
		 bool dollar_comp)
{
	struct env_entry *match;
	int found, idx;

	if (dollar_comp) {
		/*
		 * When doing $ completion, the first character should
		 * obviously be a '$'.
		 */
		if (var[0] != '$')
			return 0;

		var++;

		/*
		 * The second one, if present, should be a '{', as some
		 * configuration of the u-boot shell expand ${var} but not
		 * $var.
		 */
		if (var[0] == '{')
			var++;
		else if (var[0] != '\0')
			return 0;
	}

	idx = 0;
	found = 0;
	cmdv[0] = NULL;


	while ((idx = hmatch_r(var, idx, &match, &env_htab))) {
		int vallen = strlen(match->key) + 1;

		if (found >= maxv - 2 ||
		    bufsz < vallen + (dollar_comp ? 3 : 0))
			break;

		cmdv[found++] = buf;

		/* Add the '${' prefix to each var when doing $ completion. */
		if (dollar_comp) {
			strcpy(buf, "${");
			buf += 2;
			bufsz -= 3;
		}

		memcpy(buf, match->key, vallen);
		buf += vallen;
		bufsz -= vallen;

		if (dollar_comp) {
			/*
			 * This one is a bit odd: vallen already contains the
			 * '\0' character but we need to add the '}' suffix,
			 * hence the buf - 1 here. strcpy() will add the '\0'
			 * character just after '}'. buf is then incremented
			 * to account for the extra '}' we just added.
			 */
			strcpy(buf - 1, "}");
			buf++;
		}
	}

	qsort(cmdv, found, sizeof(cmdv[0]), strcmp_compar);

	if (idx)
		cmdv[found++] = dollar_comp ? "${...}" : "...";

	cmdv[found] = NULL;
	return found;
}
#endif
