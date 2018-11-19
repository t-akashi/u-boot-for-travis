// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI setup code
 *
 *  Copyright (c) 2016-2018 Alexander Graf et al.
 */

#include <common.h>
#include <efi_loader.h>

#if 1 /* TEMPORARILY */
#define DXE_SERVICES_TABLE_GUID \
	((efi_guid_t)EFI_GUID(0x05AD34BA, 0x6F02, 0x4214, \
		0x95, 0x2E, 0x4D, 0xA0, 0x39, 0x8E, 0x2B, 0xB9))

#define EFI_HOB_LIST_GUID \
	((efi_guid_t)EFI_GUID(0x7739F24C, 0x93D7, 0x11D4, \
		0x9A, 0x3A, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D))
#endif

#define OBJ_LIST_NOT_INITIALIZED 1

static efi_status_t efi_obj_list_initialized = OBJ_LIST_NOT_INITIALIZED;

/**
 * efi_init_platform_lang() - define supported languages
 *
 * Set the PlatformLangCodes and PlatformLang variables.
 *
 * Return:	status code
 */
static efi_status_t efi_init_platform_lang(void)
{
	efi_status_t ret;
	efi_uintn_t data_size = 0;
	char *lang = CONFIG_EFI_PLATFORM_LANG_CODES;
	char *pos;

	/*
	 * Variable PlatformLangCodes defines the language codes that the
	 * machine can support.
	 */
	ret = EFI_CALL(efi_set_variable(L"PlatformLangCodes",
					&efi_global_variable_guid,
					EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS,
					sizeof(CONFIG_EFI_PLATFORM_LANG_CODES),
					CONFIG_EFI_PLATFORM_LANG_CODES));
	if (ret != EFI_SUCCESS)
		goto out;

	/*
	 * Variable PlatformLang defines the language that the machine has been
	 * configured for.
	 */
	ret = EFI_CALL(efi_get_variable(L"PlatformLang",
					&efi_global_variable_guid,
					NULL, &data_size, &pos));
	if (ret == EFI_BUFFER_TOO_SMALL) {
		/* The variable is already set. Do not change it. */
		ret = EFI_SUCCESS;
		goto out;
	}

	/*
	 * The list of supported languages is semicolon separated. Use the first
	 * language to initialize PlatformLang.
	 */
	pos = strchr(lang, ';');
	if (pos)
		*pos = 0;

	ret = EFI_CALL(efi_set_variable(L"PlatformLang",
					&efi_global_variable_guid,
					EFI_VARIABLE_NON_VOLATILE |
					EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS,
					1 + strlen(lang), lang));
out:
	if (ret != EFI_SUCCESS)
		printf("EFI: cannot initialize platform language settings\n");
	return ret;
}

/**
 * efi_init_obj_list() - Initialize and populate EFI object list
 *
 * Return:	status code
 */
efi_status_t efi_init_obj_list(void)
{
	efi_status_t ret = EFI_SUCCESS;

	/* Initialize once only */
	if (efi_obj_list_initialized != OBJ_LIST_NOT_INITIALIZED)
		return efi_obj_list_initialized;

	/* Define supported languages */
	ret = efi_init_platform_lang();
	if (ret != EFI_SUCCESS)
		goto out;

	/* Initialize system table */
	ret = efi_initialize_system_table();
	if (ret != EFI_SUCCESS)
		goto out;

	/* Initialize root node */
	ret = efi_root_node_register();
	if (ret != EFI_SUCCESS)
		goto out;

	/* Initialize EFI driver uclass */
	ret = efi_driver_init();
	if (ret != EFI_SUCCESS)
		goto out;

	ret = efi_console_register();
	if (ret != EFI_SUCCESS)
		goto out;
#ifdef CONFIG_PARTITIONS
	ret = efi_disk_register();
	if (ret != EFI_SUCCESS)
		goto out;
#endif
#if defined(CONFIG_LCD) || defined(CONFIG_DM_VIDEO)
	ret = efi_gop_register();
	if (ret != EFI_SUCCESS)
		goto out;
#endif
#ifdef CONFIG_NET
	ret = efi_net_register();
	if (ret != EFI_SUCCESS)
		goto out;
#endif
#ifdef CONFIG_GENERATE_ACPI_TABLE
	ret = efi_acpi_register();
	if (ret != EFI_SUCCESS)
		goto out;
#endif
#ifdef CONFIG_GENERATE_SMBIOS_TABLE
	ret = efi_smbios_register();
	if (ret != EFI_SUCCESS)
		goto out;
#endif
	ret = efi_watchdog_register();
	if (ret != EFI_SUCCESS)
		goto out;

#if 1 /* TEMPORARILY */
{
	efi_guid_t guid = DXE_SERVICES_TABLE_GUID;
	/* Map within the low 32 bits, to allow for 32bit SMBIOS tables */
	u64 table = U32_MAX;
	efi_status_t ret;

	/* Reserve 4kiB page for SMBIOS */
	ret = efi_allocate_pages(EFI_ALLOCATE_MAX_ADDRESS,
				EFI_RUNTIME_SERVICES_DATA, 1, &table);
	if (ret != EFI_SUCCESS)
		return ret;

	/* And expose them to our EFI payload */
	ret = efi_install_configuration_table(&guid, (void *)(uintptr_t)table);

	guid = EFI_HOB_LIST_GUID;
	ret = efi_install_configuration_table(&guid, (void *)(uintptr_t)table);
}
#endif

	/* Initialize EFI runtime services */
	ret = efi_reset_system_init();
	if (ret != EFI_SUCCESS)
		goto out;

out:
	efi_obj_list_initialized = ret;
	return ret;
}
