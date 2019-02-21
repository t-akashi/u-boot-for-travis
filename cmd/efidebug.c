// SPDX-License-Identifier: GPL-2.0+
/*
 *  UEFI Shell-like command
 *
 *  Copyright (c) 2018 AKASHI Takahiro, Linaro Limited
 */

#include <charset.h>
#include <common.h>
#include <command.h>
#include <efi_loader.h>
#include <environment.h>
#include <exports.h>
#include <malloc.h>
#include <search.h>
#include <linux/ctype.h>

#define BS systab.boottime

/**
 * efi_get_device_handle_info() - get information of UEFI device
 *
 * @handle:		Handle of UEFI device
 * @dev_path_text:	Pointer to text of device path
 * Return:		0 on success, -1 on failure
 *
 * Currently return a formatted text of device path.
 */
static int efi_get_device_handle_info(efi_handle_t handle, u16 **dev_path_text)
{
	struct efi_device_path *dp;
	efi_status_t ret;

	ret = EFI_CALL(BS->open_protocol(handle, &efi_guid_device_path,
					 (void **)&dp, NULL /* FIXME */, NULL,
					 EFI_OPEN_PROTOCOL_GET_PROTOCOL));
	if (ret == EFI_SUCCESS) {
		*dev_path_text = efi_dp_str(dp);
		return 0;
	} else {
		return -1;
	}
}

#define EFI_HANDLE_WIDTH ((int)sizeof(efi_handle_t) * 2)

static const char spc[] = "                ";
static const char sep[] = "================";

/**
 * do_efi_show_devices() - show UEFI devices
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success, CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug "devices" sub-command.
 * Show all UEFI devices and their information.
 */
static int do_efi_show_devices(cmd_tbl_t *cmdtp, int flag,
			       int argc, char * const argv[])
{
	efi_handle_t *handles;
	efi_uintn_t num, i;
	u16 *dev_path_text;
	efi_status_t ret;

	ret = EFI_CALL(BS->locate_handle_buffer(ALL_HANDLES, NULL, NULL,
						&num, &handles));
	if (ret != EFI_SUCCESS)
		return CMD_RET_FAILURE;

	if (!num)
		return CMD_RET_SUCCESS;

	printf("Device%.*s Device Path\n", EFI_HANDLE_WIDTH - 6, spc);
	printf("%.*s ====================\n", EFI_HANDLE_WIDTH, sep);
	for (i = 0; i < num; i++) {
		if (!efi_get_device_handle_info(handles[i], &dev_path_text)) {
			printf("%p %ls\n", handles[i], dev_path_text);
			efi_free_pool(dev_path_text);
		}
	}

	EFI_CALL(BS->free_pool(handles));

	return CMD_RET_SUCCESS;
}

/**
 * do_efi_boot_add() - set UEFI boot option
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success,
 *		CMD_RET_USAGE or CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug "boot add" sub-command.
 * Create or change UEFI boot option.
 *   - boot add <id> <label> <interface> <devnum>[:<part>] <file> <options>
 */
static int do_efi_boot_add(cmd_tbl_t *cmdtp, int flag,
			   int argc, char * const argv[])
{
	int id;
	char *endp;
	char var_name[9];
	u16 var_name16[9], *p;
	efi_guid_t guid;
	size_t label_len, label_len16;
	u16 *label;
	struct efi_device_path *device_path = NULL, *file_path = NULL;
	struct efi_load_option lo;
	void *data = NULL;
	efi_uintn_t size;
	int ret;

	if (argc < 6 || argc > 7)
		return CMD_RET_USAGE;

	id = (int)simple_strtoul(argv[1], &endp, 16);
	if (*endp != '\0' || id > 0xffff)
		return CMD_RET_FAILURE;

	sprintf(var_name, "Boot%04X", id);
	p = var_name16;
	utf8_utf16_strncpy(&p, var_name, 9);

	guid = efi_global_variable_guid;

	/* attributes */
	lo.attributes = 0x1; /* always ACTIVE */

	/* label */
	label_len = strlen(argv[2]);
	label_len16 = utf8_utf16_strnlen(argv[2], label_len);
	label = malloc((label_len16 + 1) * sizeof(u16));
	if (!label)
		return CMD_RET_FAILURE;
	lo.label = label; /* label will be changed below */
	utf8_utf16_strncpy(&label, argv[2], label_len);

	/* file path */
	ret = efi_dp_from_name(argv[3], argv[4], argv[5], &device_path,
			       &file_path);
	if (ret != EFI_SUCCESS) {
		printf("Cannot create device path for \"%s %s\"\n",
		       argv[3], argv[4]);
		ret = CMD_RET_FAILURE;
		goto out;
	}
	lo.file_path = file_path;
	lo.file_path_length = efi_dp_size(file_path)
				+ sizeof(struct efi_device_path); /* for END */

	/* optional data */
	lo.optional_data = (u8 *)(argc == 6 ? "" : argv[6]);

	size = efi_serialize_load_option(&lo, (u8 **)&data);
	if (!size) {
		ret = CMD_RET_FAILURE;
		goto out;
	}

	ret = efi_set_variable(var_name16, &guid,
			       EFI_VARIABLE_BOOTSERVICE_ACCESS |
			       EFI_VARIABLE_RUNTIME_ACCESS, size, data);
	ret = (ret == EFI_SUCCESS ? CMD_RET_SUCCESS : CMD_RET_FAILURE);
out:
	free(data);
	efi_free_pool(device_path);
	efi_free_pool(file_path);
	free(lo.label);

	return ret;
}

/**
 * do_efi_boot_rm() - delete UEFI boot options
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success, CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug "boot rm" sub-command.
 * Delete UEFI boot options.
 *   - boot rm <id> ...
 */
static int do_efi_boot_rm(cmd_tbl_t *cmdtp, int flag,
			  int argc, char * const argv[])
{
	efi_guid_t guid;
	int id, i;
	char *endp;
	char var_name[9];
	u16 var_name16[9];
	efi_status_t ret;

	if (argc == 1)
		return CMD_RET_USAGE;

	guid = efi_global_variable_guid;
	for (i = 1; i < argc; i++, argv++) {
		id = (int)simple_strtoul(argv[1], &endp, 16);
		if (*endp != '\0' || id > 0xffff)
			return CMD_RET_FAILURE;

		sprintf(var_name, "Boot%04X", id);
		utf8_utf16_strncpy((u16 **)&var_name16, var_name, 9);

		ret = efi_set_variable(var_name16, &guid, 0, 0, NULL);
		if (ret) {
			printf("cannot remove Boot%04X", id);
			return CMD_RET_FAILURE;
		}
	}

	return CMD_RET_SUCCESS;
}

/**
 * show_efi_boot_opt_data() - dump UEFI boot option
 *
 * @id:		Boot opton number
 * @data:	Value of UEFI boot option variable
 *
 * Decode the value of UEFI boot option variable and print information.
 */
static void show_efi_boot_opt_data(int id, void *data)
{
	struct efi_load_option lo;
	char *label, *p;
	size_t label_len16, label_len;
	u16 *dp_str;

	efi_deserialize_load_option(&lo, data);

	label_len16 = u16_strlen(lo.label);
	label_len = utf16_utf8_strnlen(lo.label, label_len16);
	label = malloc(label_len + 1);
	if (!label)
		return;
	p = label;
	utf16_utf8_strncpy(&p, lo.label, label_len16);

	printf("Boot%04X:\n", id);
	printf("\tattributes: %c%c%c (0x%08x)\n",
	       /* ACTIVE */
	       lo.attributes & 0x1 ? 'A' : '-',
	       /* FORCE RECONNECT */
	       lo.attributes & 0x2 ? 'R' : '-',
	       /* HIDDEN */
	       lo.attributes & 0x8 ? 'H' : '-',
	       lo.attributes);
	printf("\tlabel: %s\n", label);

	dp_str = efi_dp_str(lo.file_path);
	printf("\tfile_path: %ls\n", dp_str);
	efi_free_pool(dp_str);

	printf("\tdata: %s\n", lo.optional_data);

	free(label);
}

/**
 * show_efi_boot_opt() - dump UEFI boot option
 *
 * @id:		Boot opton number
 *
 * Dump information defined by UEFI boot option.
 */
static void show_efi_boot_opt(int id)
{
	char var_name[9];
	u16 var_name16[9], *p;
	efi_guid_t guid;
	void *data = NULL;
	efi_uintn_t size;
	int ret;

	sprintf(var_name, "Boot%04X", id);
	p = var_name16;
	utf8_utf16_strncpy(&p, var_name, 9);
	guid = efi_global_variable_guid;

	size = 0;
	ret = efi_get_variable(var_name16, &guid, NULL, &size, NULL);
	if (ret == (int)EFI_BUFFER_TOO_SMALL) {
		data = malloc(size);
		ret = efi_get_variable(var_name16, &guid, NULL, &size, data);
	}
	if (ret == EFI_SUCCESS)
		show_efi_boot_opt_data(id, data);
	else if (ret == EFI_NOT_FOUND)
		printf("Boot%04X: not found\n", id);

	free(data);
}

/**
 * show_efi_boot_dump() - dump all UEFI boot options
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success, CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug "boot dump" sub-command.
 * Dump information of all UEFI boot options defined.
 *   - boot dump
 */
static int do_efi_boot_dump(cmd_tbl_t *cmdtp, int flag,
			    int argc, char * const argv[])
{
	char regex[256];
	char * const regexlist[] = {regex};
	char *variables = NULL, *boot, *value;
	int len;
	int id;

	if (argc > 1)
		return CMD_RET_USAGE;

	snprintf(regex, 256, "efi_.*-.*-.*-.*-.*_Boot[0-9A-F]+");

	/* TODO: use GetNextVariableName? */
	len = hexport_r(&env_htab, '\n', H_MATCH_REGEX | H_MATCH_KEY,
			&variables, 0, 1, regexlist);

	if (!len)
		return CMD_RET_SUCCESS;

	if (len < 0)
		return CMD_RET_FAILURE;

	boot = variables;
	while (*boot) {
		value = strstr(boot, "Boot") + 4;
		id = (int)simple_strtoul(value, NULL, 16);
		show_efi_boot_opt(id);
		boot = strchr(boot, '\n');
		if (!*boot)
			break;
		boot++;
	}
	free(variables);

	return CMD_RET_SUCCESS;
}

/**
 * show_efi_boot_order() - show order of UEFI boot options
 *
 * Return:	CMD_RET_SUCCESS on success, CMD_RET_RET_FAILURE on failure
 *
 * Show order of UEFI boot options defined by BootOrder variable.
 */
static int show_efi_boot_order(void)
{
	efi_guid_t guid;
	u16 *bootorder = NULL;
	efi_uintn_t size;
	int num, i;
	char var_name[9];
	u16 var_name16[9], *p16;
	void *data;
	struct efi_load_option lo;
	char *label, *p;
	size_t label_len16, label_len;
	efi_status_t ret;

	guid = efi_global_variable_guid;
	size = 0;
	ret = efi_get_variable(L"BootOrder", &guid, NULL, &size, NULL);
	if (ret == EFI_BUFFER_TOO_SMALL) {
		bootorder = malloc(size);
		ret = efi_get_variable(L"BootOrder", &guid, NULL, &size,
				       bootorder);
	}
	if (ret == EFI_NOT_FOUND) {
		printf("BootOrder not defined\n");
		ret = CMD_RET_SUCCESS;
		goto out;
	} else if (ret != EFI_SUCCESS) {
		ret = CMD_RET_FAILURE;
		goto out;
	}

	num = size / sizeof(u16);
	for (i = 0; i < num; i++) {
		sprintf(var_name, "Boot%04X", bootorder[i]);
		p16 = var_name16;
		utf8_utf16_strncpy(&p16, var_name, 9);

		size = 0;
		ret = efi_get_variable(var_name16, &guid, NULL, &size, NULL);
		if (ret != EFI_BUFFER_TOO_SMALL) {
			printf("%2d: Boot%04X: (not defined)\n",
			       i + 1, bootorder[i]);
			continue;
		}

		data = malloc(size);
		if (!data) {
			ret = CMD_RET_FAILURE;
			goto out;
		}
		ret = efi_get_variable(var_name16, &guid, NULL, &size, data);
		if (ret != EFI_SUCCESS) {
			free(data);
			ret = CMD_RET_FAILURE;
			goto out;
		}

		efi_deserialize_load_option(&lo, data);

		label_len16 = u16_strlen(lo.label);
		label_len = utf16_utf8_strnlen(lo.label, label_len16);
		label = malloc(label_len + 1);
		if (!label) {
			free(data);
			ret = CMD_RET_FAILURE;
			goto out;
		}
		p = label;
		utf16_utf8_strncpy(&p, lo.label, label_len16);
		printf("%2d: Boot%04X: %s\n", i + 1, bootorder[i], label);
		free(label);

		free(data);
	}
out:
	free(bootorder);

	return ret;
}

/**
 * do_efi_boot_next() - manage UEFI BootNext variable
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success,
 *		CMD_RET_USAGE or CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug "boot next" sub-command.
 * Set BootNext variable.
 *   - boot next <id>
 */
static int do_efi_boot_next(cmd_tbl_t *cmdtp, int flag,
			    int argc, char * const argv[])
{
	u16 bootnext;
	efi_uintn_t size;
	char *endp;
	efi_guid_t guid;
	efi_status_t ret;

	if (argc != 2)
		return CMD_RET_USAGE;

	bootnext = (u16)simple_strtoul(argv[1], &endp, 16);
	if (*endp != '\0' || bootnext > 0xffff) {
		printf("invalid value: %s\n", argv[1]);
		ret = CMD_RET_FAILURE;
		goto out;
	}

	guid = efi_global_variable_guid;
	size = sizeof(u16);
	ret = efi_set_variable(L"BootNext", &guid,
			       EFI_VARIABLE_BOOTSERVICE_ACCESS |
			       EFI_VARIABLE_RUNTIME_ACCESS, size, &bootnext);
	ret = (ret == EFI_SUCCESS ? CMD_RET_SUCCESS : CMD_RET_FAILURE);
out:
	return ret;
}

/**
 * do_efi_boot_order() - manage UEFI BootOrder variable
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success, CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug "boot order" sub-command.
 * Show order of UEFI boot options, or change it in BootOrder variable.
 *   - boot order [<id> ...]
 */
static int do_efi_boot_order(cmd_tbl_t *cmdtp, int flag,
			     int argc, char * const argv[])
{
	u16 *bootorder = NULL;
	efi_uintn_t size;
	int id, i;
	char *endp;
	efi_guid_t guid;
	efi_status_t ret;

	if (argc == 1)
		return show_efi_boot_order();

	argc--;
	argv++;

	size = argc * sizeof(u16);
	bootorder = malloc(size);
	if (!bootorder)
		return CMD_RET_FAILURE;

	for (i = 0; i < argc; i++) {
		id = (int)simple_strtoul(argv[i], &endp, 16);
		if (*endp != '\0' || id > 0xffff) {
			printf("invalid value: %s\n", argv[i]);
			ret = CMD_RET_FAILURE;
			goto out;
		}

		bootorder[i] = (u16)id;
	}

	guid = efi_global_variable_guid;
	ret = efi_set_variable(L"BootOrder", &guid,
			       EFI_VARIABLE_BOOTSERVICE_ACCESS |
			       EFI_VARIABLE_RUNTIME_ACCESS, size, bootorder);
	ret = (ret == EFI_SUCCESS ? CMD_RET_SUCCESS : CMD_RET_FAILURE);
out:
	free(bootorder);

	return ret;
}

static cmd_tbl_t cmd_efidebug_boot_sub[] = {
	U_BOOT_CMD_MKENT(add, CONFIG_SYS_MAXARGS, 1, do_efi_boot_add, "", ""),
	U_BOOT_CMD_MKENT(rm, CONFIG_SYS_MAXARGS, 1, do_efi_boot_rm, "", ""),
	U_BOOT_CMD_MKENT(dump, CONFIG_SYS_MAXARGS, 1, do_efi_boot_dump, "", ""),
	U_BOOT_CMD_MKENT(next, CONFIG_SYS_MAXARGS, 1, do_efi_boot_next, "", ""),
	U_BOOT_CMD_MKENT(order, CONFIG_SYS_MAXARGS, 1, do_efi_boot_order,
			 "", ""),
};

/**
 * do_efi_boot_opt() - manage UEFI boot options
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success,
 *		CMD_RET_USAGE or CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug "boot" sub-command.
 * See above for details of sub-commands.
 */
static int do_efi_boot_opt(cmd_tbl_t *cmdtp, int flag,
			   int argc, char * const argv[])
{
	cmd_tbl_t *cp;

	if (argc < 2)
		return CMD_RET_USAGE;

	argc--; argv++;

	cp = find_cmd_tbl(argv[0], cmd_efidebug_boot_sub,
			  ARRAY_SIZE(cmd_efidebug_boot_sub));
	if (!cp)
		return CMD_RET_USAGE;

	return cp->cmd(cmdtp, flag, argc, argv);
}

static cmd_tbl_t cmd_efidebug_sub[] = {
	U_BOOT_CMD_MKENT(boot, CONFIG_SYS_MAXARGS, 1, do_efi_boot_opt, "", ""),
	U_BOOT_CMD_MKENT(devices, CONFIG_SYS_MAXARGS, 1, do_efi_show_devices,
			 "", ""),
};

/**
 * do_efidebug() - display and configure UEFI environment
 *
 * @cmdtp:	Command table
 * @flag:	Command flag
 * @argc:	Number of arguments
 * @argv:	Argument array
 * Return:	CMD_RET_SUCCESS on success,
 *		CMD_RET_USAGE or CMD_RET_RET_FAILURE on failure
 *
 * Implement efidebug command which allows us to dsiplay and
 * configure UEFI environment.
 * See above for details of sub-commands.
 */
static int do_efidebug(cmd_tbl_t *cmdtp, int flag,
		       int argc, char * const argv[])
{
	cmd_tbl_t *cp;
	efi_status_t r;

	if (argc < 2)
		return CMD_RET_USAGE;

	argc--; argv++;

	/* Initialize UEFI drivers */
	r = efi_init_obj_list();
	if (r != EFI_SUCCESS) {
		printf("Error: Cannot initialize UEFI sub-system, r = %lu\n",
		       r & ~EFI_ERROR_MASK);
		return CMD_RET_FAILURE;
	}

	cp = find_cmd_tbl(argv[0], cmd_efidebug_sub,
			  ARRAY_SIZE(cmd_efidebug_sub));
	if (!cp)
		return CMD_RET_USAGE;

	return cp->cmd(cmdtp, flag, argc, argv);
}

#ifdef CONFIG_SYS_LONGHELP
static char efidebug_help_text[] =
	"  - UEFI Shell-like interface to configure UEFI environment\n"
	"\n"
	"efidebug boot add <bootid> <label> <interface> <devnum>[:<part>] <file path> [<load options>]\n"
	"  - set UEFI BootXXXX variable\n"
	"    <load options> will be passed to UEFI application\n"
	"efidebug boot rm <bootid#1> [<bootid#2> [<bootid#3> [...]]]\n"
	"  - delete UEFI BootXXXX variables\n"
	"efidebug boot dump\n"
	"  - dump all UEFI BootXXXX variables\n"
	"efidebug boot next <bootid>\n"
	"  - set UEFI BootNext variable\n"
	"efidebug boot order [<bootid#1> [<bootid#2> [<bootid#3> [...]]]]\n"
	"  - set/show UEFI boot order\n"
	"\n"
	"efidebug devices\n"
	"  - show uefi devices\n";
#endif

U_BOOT_CMD(
	efidebug, 10, 0, do_efidebug,
	"Configure UEFI environment",
	efidebug_help_text
);
