// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Google, Inc
 * Written by Simon Glass <sjg@chromium.org>
 */

#include <common.h>
#include <environment.h>

DECLARE_GLOBAL_DATA_PTR;

#if defined(CONFIG_NEEDS_MANUAL_RELOC)
void env_fix_drivers(void)
{
	struct env_driver *drv;
	const int n_ents = ll_entry_count(struct env_driver, env_driver);
	struct env_driver *entry;

	drv = ll_entry_start(struct env_driver, env_driver);
	for (entry = drv; entry != drv + n_ents; entry++) {
		if (entry->name)
			entry->name += gd->reloc_off;
		if (entry->load)
			entry->load += gd->reloc_off;
		if (entry->save)
			entry->save += gd->reloc_off;
#ifdef CONFIG_ENV_EFI
		if (entry->efi_load)
			entry->efi_load += gd->reloc_off;
		if (entry->efi_save)
			entry->efi_save += gd->reloc_off;
#endif
		if (entry->init)
			entry->init += gd->reloc_off;
	}
}
#endif

static struct env_driver *_env_driver_lookup(enum env_location loc)
{
	struct env_driver *drv;
	const int n_ents = ll_entry_count(struct env_driver, env_driver);
	struct env_driver *entry;

	drv = ll_entry_start(struct env_driver, env_driver);
	for (entry = drv; entry != drv + n_ents; entry++) {
		if (loc == entry->location)
			return entry;
	}

	/* Not found */
	return NULL;
}

static enum env_location env_locations[] = {
#ifdef CONFIG_ENV_IS_IN_EEPROM
	ENVL_EEPROM,
#endif
#ifdef CONFIG_ENV_IS_IN_EXT4
	ENVL_EXT4,
#endif
#ifdef CONFIG_ENV_IS_IN_FAT
	ENVL_FAT,
#endif
#ifdef CONFIG_ENV_IS_IN_FLASH
	ENVL_FLASH,
#endif
#ifdef CONFIG_ENV_IS_IN_MMC
	ENVL_MMC,
#endif
#ifdef CONFIG_ENV_IS_IN_NAND
	ENVL_NAND,
#endif
#ifdef CONFIG_ENV_IS_IN_NVRAM
	ENVL_NVRAM,
#endif
#ifdef CONFIG_ENV_IS_IN_REMOTE
	ENVL_REMOTE,
#endif
#ifdef CONFIG_ENV_IS_IN_SATA
	ENVL_ESATA,
#endif
#ifdef CONFIG_ENV_IS_IN_SPI_FLASH
	ENVL_SPI_FLASH,
#endif
#ifdef CONFIG_ENV_IS_IN_UBI
	ENVL_UBI,
#endif
#ifdef CONFIG_ENV_IS_NOWHERE
	ENVL_NOWHERE,
#endif
};

static bool env_has_inited(enum env_location location)
{
	return gd->env_has_init & BIT(location);
}

static void env_set_inited(enum env_location location)
{
	/*
	 * We're using a 32-bits bitmask stored in gd (env_has_init)
	 * using the above enum value as the bit index. We need to
	 * make sure that we're not overflowing it.
	 */
	BUILD_BUG_ON(ARRAY_SIZE(env_locations) > BITS_PER_LONG);

	gd->env_has_init |= BIT(location);
}

/**
 * env_get_location() - Returns the best env location for a board
 * @op: operations performed on the environment
 * @prio: priority between the multiple environments, 0 being the
 *        highest priority
 *
 * This will return the preferred environment for the given priority.
 * This is overridable by boards if they need to.
 *
 * All implementations are free to use the operation, the priority and
 * any other data relevant to their choice, but must take into account
 * the fact that the lowest prority (0) is the most important location
 * in the system. The following locations should be returned by order
 * of descending priorities, from the highest to the lowest priority.
 *
 * Returns:
 * an enum env_location value on success, a negative error code otherwise
 */
__weak enum env_location env_get_location(enum env_operation op, int prio)
{
	if (prio >= ARRAY_SIZE(env_locations))
		return ENVL_UNKNOWN;

	if (op != ENVOP_EFI)
		gd->env_load_prio = prio;

	return env_locations[prio];
}


/**
 * env_driver_lookup() - Finds the most suited environment location
 * @op: operations performed on the environment
 * @prio: priority between the multiple environments, 0 being the
 *        highest priority
 *
 * This will try to find the available environment with the highest
 * priority in the system.
 *
 * Returns:
 * NULL on error, a pointer to a struct env_driver otherwise
 */
static struct env_driver *env_driver_lookup(enum env_operation op, int prio)
{
	enum env_location loc = env_get_location(op, prio);
	struct env_driver *drv;

	if (loc == ENVL_UNKNOWN)
		return NULL;

	drv = _env_driver_lookup(loc);
	if (!drv) {
		debug("%s: No environment driver for location %d\n", __func__,
		      loc);
		return NULL;
	}

	return drv;
}

__weak int env_get_char_spec(int index)
{
	return *(uchar *)(gd->env_addr + index);
}

int env_get_char(int index)
{
	if (gd->env_valid == ENV_INVALID)
		return default_environment[index];
	else
		return env_get_char_spec(index);
}

int env_load(void)
{
	struct env_driver *drv;
	int best_prio = -1;
	int prio;

	for (prio = 0; (drv = env_driver_lookup(ENVOP_LOAD, prio)); prio++) {
		int ret;

		if (!drv->load)
			continue;

		if (!env_has_inited(drv->location))
			continue;

		printf("Loading Environment from %s... ", drv->name);
		/*
		 * In error case, the error message must be printed during
		 * drv->load() in some underlying API, and it must be exactly
		 * one message.
		 */
		ret = drv->load();
		if (!ret) {
			printf("OK\n");
			return 0;
		} else if (ret == -ENOMSG) {
			/* Handle "bad CRC" case */
			if (best_prio == -1)
				best_prio = prio;
		} else {
			debug("Failed (%d)\n", ret);
		}
	}

	/*
	 * In case of invalid environment, we set the 'default' env location
	 * to the best choice, i.e.:
	 *   1. Environment location with bad CRC, if such location was found
	 *   2. Otherwise use the location with highest priority
	 *
	 * This way, next calls to env_save() will restore the environment
	 * at the right place.
	 */
	if (best_prio >= 0)
		debug("Selecting environment with bad CRC\n");
	else
		best_prio = 0;
	env_get_location(ENVOP_LOAD, best_prio);

	return -ENODEV;
}

int env_save(void)
{
	struct env_driver *drv;

	drv = env_driver_lookup(ENVOP_SAVE, gd->env_load_prio);
	if (drv) {
		int ret;

		if (!drv->save)
			return -ENODEV;

		if (!env_has_inited(drv->location))
			return -ENODEV;

		printf("Saving Environment to %s... ", drv->name);
		ret = drv->save();
		if (ret)
			printf("Failed (%d)\n", ret);
		else
			printf("OK\n");

		if (!ret)
			return 0;
	}

	return -ENODEV;
}

int env_init(void)
{
	struct env_driver *drv;
	int ret = -ENOENT;
	int prio;

	for (prio = 0; (drv = env_driver_lookup(ENVOP_INIT, prio)); prio++) {
		if (!drv->init || !(ret = drv->init()))
			env_set_inited(drv->location);

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

#ifdef CONFIG_ENV_EFI
struct hsearch_data efi_var_htab;
struct hsearch_data efi_nv_var_htab;

int env_efi_import(const char *buf, int check)
{
	env_t *ep = (env_t *)buf;

	if (check) {
		u32 crc;

		memcpy(&crc, &ep->crc, sizeof(crc));

		if (crc32(0, ep->data, CONFIG_ENV_EFI_SIZE - ENV_HEADER_SIZE)
				!= crc) {
			pr_err("bad CRC of UEFI variables\n");
			return -ENOMSG; /* needed for env_load() */
		}
	}

	if (himport_r(&efi_nv_var_htab, (char *)ep->data,
		      CONFIG_ENV_EFI_SIZE - ENV_HEADER_SIZE,
		      '\0', 0, 0, 0, NULL))
		return 0;

	pr_err("Cannot import environment: errno = %d\n", errno);

	/* set_default_env("import failed", 0); */

	return -EIO;
}

int env_efi_export(env_t *env_out)
{
	char *res;
	ssize_t	len;

	res = (char *)env_out->data;
	len = hexport_r(&efi_nv_var_htab, '\0', 0, &res,
			CONFIG_ENV_EFI_SIZE - ENV_HEADER_SIZE,
			0, NULL);
	if (len < 0) {
		pr_err("Cannot export environment: errno = %d\n", errno);
		return 1;
	}

	env_out->crc = crc32(0, env_out->data,
			     CONFIG_ENV_EFI_SIZE - ENV_HEADER_SIZE);

	return 0;
}

int env_efi_save(void)
{
#ifdef CONFIG_ENV_IS_NOWHERE
	return 0;
#else
	struct env_driver *drv = NULL;
	int ret;

	if (!efi_nv_var_htab.table)
		return 0;

	if (gd->env_efi_prio == -1) {
		pr_warn("No UEFI non-volatile variable storage\n");
		return -1;
	}

	drv = _env_driver_lookup(env_get_location(ENVOP_EFI, gd->env_efi_prio));
	if (!drv) {
		pr_warn("No UEFI non-volatile variable storage\n");
		return -1;
	}

	ret = drv->efi_save();
	if (ret)
		pr_err("Saving UEFI non-volatile variable failed\n");

	return ret;
#endif
}

/* This function should be called only once at init */
int env_efi_load(void)
{
#ifndef CONFIG_ENV_IS_NOWHERE
	struct env_driver *drv;
	int prio;
	enum env_location loc;
#endif
	int ret;

	/* volatile variables */
	if (!efi_var_htab.table) {
		ret = himport_r(&efi_var_htab, NULL, 0, '\0', 0, 0, 0, NULL);
		if (!ret) {
			pr_err("Creating UEFI volatile variables failed\n");
			return -1;
		}
	}

#ifndef CONFIG_ENV_IS_NOWHERE
	gd->env_efi_prio = -1;

	/* non-volatile variables */
	if (efi_nv_var_htab.table)
		return 0;

	for (drv = NULL, prio = 0; prio < ARRAY_SIZE(env_locations); prio++) {
		loc = env_get_location(ENVOP_EFI, prio);
		drv = _env_driver_lookup(loc);
		if (!drv)
			continue;

		if (drv->efi_load && drv->efi_save)
			break;
	}
	if (!drv || prio == ARRAY_SIZE(env_locations)) {
		pr_warn("No UEFI non-volatile variable storage\n");
		goto skip_load;
	}

	gd->env_efi_prio = prio;

	ret = drv->efi_load();
	if (ret) {
		pr_err("Loading UEFI non-volatile variables failed\n");
		return -1;
	}
skip_load:
#endif /* CONFIG_ENV_IS_NOWHERE */

	if (!efi_nv_var_htab.table) {
		ret = himport_r(&efi_nv_var_htab, NULL, 0, '\0', 0, 0, 0, NULL);
		if (!ret) {
			pr_err("Creating UEFI non-volatile variables failed\n");
			return -1;
		}

		return 0;
	}

	return 0;
}
#endif /* CONFIG_ENV_EFI */
