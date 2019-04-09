// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI utils
 *
 *  Copyright (c) 2017 Rob Clark
 */

#include <malloc.h>
#include <charset.h>
#include <efi_loader.h>
#include <hexdump.h>
#include <environment.h>
#include <search.h>
#include <uuid.h>

#define READ_ONLY BIT(31)

/*
 * Mapping between EFI variables and u-boot variables:
 *
 *   efi_$guid_$varname = {attributes}(type)value
 *
 * For example:
 *
 *   efi_8be4df61-93ca-11d2-aa0d-00e098032b8c_OsIndicationsSupported=
 *      "{ro,boot,run}(blob)0000000000000000"
 *   efi_8be4df61-93ca-11d2-aa0d-00e098032b8c_BootOrder=
 *      "(blob)00010000"
 *
 * The attributes are a comma separated list of these possible
 * attributes:
 *
 *   + ro   - read-only
 *   + boot - boot-services access
 *   + run  - runtime access
 *
 * NOTE: with current implementation, no variables are available after
 * ExitBootServices, and all are persisted (if possible).
 *
 * If not specified, the attributes default to "{boot}".
 *
 * The required type is one of:
 *
 *   + utf8 - raw utf8 string
 *   + blob - arbitrary length hex string
 *
 * Maybe a utf16 type would be useful to for a string value to be auto
 * converted to utf16?
 */

/*
 * We will maintain two variable database: one for volatile variables,
 * the other for non-volatile variables. The former exists only in memory
 * and will go away at re-boot. The latter is currently backed up by the same
 * device as U-Boot environment and also works as variables cache.
 *
 *	struct hsearch_data efi_var_htab
 *	struct hsearch_data efi_nv_var_htab
 */

static char *env_efi_get(const char *name, bool is_non_volatile)
{
	struct hsearch_data *htab;
	ENTRY e, *ep;

	/* WATCHDOG_RESET(); */

	if (is_non_volatile)
		htab = &efi_nv_var_htab;
	else
		htab = &efi_var_htab;

	e.key   = name;
	e.data  = NULL;
	hsearch_r(e, FIND, &ep, htab, 0);

	return ep ? ep->data : NULL;
}

static int env_efi_set(const char *name, const char *value,
		       bool is_non_volatile)
{
	struct hsearch_data *htab;
	ENTRY e, *ep;
	int ret;

	if (is_non_volatile)
		htab = &efi_nv_var_htab;
	else
		htab = &efi_var_htab;

	/* delete */
	if (!value || *value == '\0') {
		ret = hdelete_r(name, htab, H_PROGRAMMATIC);
		return !ret;
	}

	/* set */
	e.key   = name;
	e.data  = (char *)value;
	hsearch_r(e, ENTER, &ep, htab, H_PROGRAMMATIC);
	if (!ep) {
		printf("## Error inserting \"%s\" variable, errno=%d\n",
		       name, errno);
		return 1;
	}

	return 0;
}

#define PREFIX_LEN (strlen("efi_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx_"))

/**
 * efi_to_native() - convert the UEFI variable name and vendor GUID to U-Boot
 *		     variable name
 *
 * The U-Boot variable name is a concatenation of prefix 'efi', the hexstring
 * encoded vendor GUID, and the UTF-8 encoded UEFI variable name separated by
 * underscores, e.g. 'efi_8be4df61-93ca-11d2-aa0d-00e098032b8c_BootOrder'.
 *
 * @native:		pointer to pointer to U-Boot variable name
 * @variable_name:	UEFI variable name
 * @vendor:		vendor GUID
 * Return:		status code
 */
static efi_status_t efi_to_native(char **native, const u16 *variable_name,
				  const efi_guid_t *vendor)
{
	size_t len;
	char *pos;

	len = PREFIX_LEN + utf16_utf8_strlen(variable_name) + 1;
	*native = malloc(len);
	if (!*native)
		return EFI_OUT_OF_RESOURCES;

	pos = *native;
	pos += sprintf(pos, "efi_%pUl_", vendor);
	utf16_utf8_strcpy(&pos, variable_name);

	return EFI_SUCCESS;
}

/**
 * prefix() - skip over prefix
 *
 * Skip over a prefix string.
 *
 * @str:	string with prefix
 * @prefix:	prefix string
 * Return:	string without prefix, or NULL if prefix not found
 */
static const char *prefix(const char *str, const char *prefix)
{
	size_t n = strlen(prefix);
	if (!strncmp(prefix, str, n))
		return str + n;
	return NULL;
}

/**
 * parse_attr() - decode attributes part of variable value
 *
 * Convert the string encoded attributes of a UEFI variable to a bit mask.
 * TODO: Several attributes are not supported.
 *
 * @str:	value of U-Boot variable
 * @attrp:	pointer to UEFI attributes
 * Return:	pointer to remainder of U-Boot variable value
 */
static const char *parse_attr(const char *str, u32 *attrp)
{
	u32 attr = 0;
	char sep = '{';

	if (*str != '{') {
		*attrp = EFI_VARIABLE_BOOTSERVICE_ACCESS;
		return str;
	}

	while (*str == sep) {
		const char *s;

		str++;

		if ((s = prefix(str, "ro"))) {
			attr |= READ_ONLY;
		} else if ((s = prefix(str, "nv"))) {
			attr |= EFI_VARIABLE_NON_VOLATILE;
		} else if ((s = prefix(str, "boot"))) {
			attr |= EFI_VARIABLE_BOOTSERVICE_ACCESS;
		} else if ((s = prefix(str, "run"))) {
			attr |= EFI_VARIABLE_RUNTIME_ACCESS;
		} else {
			printf("invalid attribute: %s\n", str);
			break;
		}

		str = s;
		sep = ',';
	}

	str++;

	*attrp = attr;

	return str;
}

static
efi_status_t EFIAPI efi_get_variable_common(u16 *variable_name,
					    const efi_guid_t *vendor,
					    u32 *attributes,
					    efi_uintn_t *data_size, void *data,
					    bool is_non_volatile)
{
	char *native_name;
	efi_status_t ret;
	unsigned long in_size;
	const char *val, *s;
	u32 attr;

	if (!variable_name || !vendor || !data_size)
		return EFI_EXIT(EFI_INVALID_PARAMETER);

	ret = efi_to_native(&native_name, variable_name, vendor);
	if (ret)
		return ret;

	EFI_PRINT("get '%s'\n", native_name);

	val = env_efi_get(native_name, is_non_volatile);
	free(native_name);
	if (!val)
		return EFI_NOT_FOUND;

	val = parse_attr(val, &attr);

	in_size = *data_size;

	if ((s = prefix(val, "(blob)"))) {
		size_t len = strlen(s);

		/* number of hexadecimal digits must be even */
		if (len & 1)
			return EFI_DEVICE_ERROR;

		/* two characters per byte: */
		len /= 2;
		*data_size = len;

		if (in_size < len) {
			ret = EFI_BUFFER_TOO_SMALL;
			goto out;
		}

		if (!data)
			return EFI_INVALID_PARAMETER;

		if (hex2bin(data, s, len))
			return EFI_DEVICE_ERROR;

		EFI_PRINT("got value: \"%s\"\n", s);
	} else if ((s = prefix(val, "(utf8)"))) {
		unsigned len = strlen(s) + 1;

		*data_size = len;

		if (in_size < len) {
			ret = EFI_BUFFER_TOO_SMALL;
			goto out;
		}

		if (!data)
			return EFI_INVALID_PARAMETER;

		memcpy(data, s, len);
		((char *)data)[len] = '\0';

		EFI_PRINT("got value: \"%s\"\n", (char *)data);
	} else {
		EFI_PRINT("invalid value: '%s'\n", val);
		return EFI_DEVICE_ERROR;
	}

out:
	if (attributes)
		*attributes = attr & EFI_VARIABLE_MASK;

	return ret;
}

static
efi_status_t EFIAPI efi_get_volatile_variable(u16 *variable_name,
					      const efi_guid_t *vendor,
					      u32 *attributes,
					      efi_uintn_t *data_size,
					      void *data)
{
	return efi_get_variable_common(variable_name, vendor, attributes,
				       data_size, data, false);
}

efi_status_t EFIAPI efi_get_nonvolatile_variable(u16 *variable_name,
						 const efi_guid_t *vendor,
						 u32 *attributes,
						 efi_uintn_t *data_size,
						 void *data)
{
	return efi_get_variable_common(variable_name, vendor, attributes,
				       data_size, data, true);
}

/**
 * efi_efi_get_variable() - retrieve value of a UEFI variable
 *
 * This function implements the GetVariable runtime service.
 *
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @variable_name:	name of the variable
 * @vendor:		vendor GUID
 * @attributes:		attributes of the variable
 * @data_size:		size of the buffer to which the variable value is copied
 * @data:		buffer to which the variable value is copied
 * Return:		status code
 */
efi_status_t EFIAPI efi_get_variable(u16 *variable_name,
				     const efi_guid_t *vendor, u32 *attributes,
				     efi_uintn_t *data_size, void *data)
{
	efi_status_t ret;

	EFI_ENTRY("\"%ls\" %pUl %p %p %p", variable_name, vendor, attributes,
		  data_size, data);

	ret = efi_get_volatile_variable(variable_name, vendor, attributes,
					data_size, data);
	if (ret == EFI_NOT_FOUND)
		ret = efi_get_nonvolatile_variable(variable_name, vendor,
						   attributes, data_size, data);

	return EFI_EXIT(ret);
}

static char *efi_variables_list;
static char *efi_cur_variable;

/**
 * parse_uboot_variable() - parse a u-boot variable and get uefi-related
 *			    information
 * @variable:		whole data of u-boot variable (ie. name=value)
 * @variable_name_size: size of variable_name buffer in byte
 * @variable_name:	name of uefi variable in u16, null-terminated
 * @vendor:		vendor's guid
 * @attributes:		attributes
 *
 * A uefi variable is encoded into a u-boot variable as described above.
 * This function parses such a u-boot variable and retrieve uefi-related
 * information into respective parameters. In return, variable_name_size
 * is the size of variable name including NULL.
 *
 * Return:		EFI_SUCCESS if parsing is OK, EFI_NOT_FOUND when
			the entire variable list has been returned,
			otherwise non-zero status code
 */
static efi_status_t parse_uboot_variable(char *variable,
					 efi_uintn_t *variable_name_size,
					 u16 *variable_name,
					 const efi_guid_t *vendor,
					 u32 *attributes)
{
	char *guid, *name, *end, c;
	unsigned long name_len;
	u16 *p;

	guid = strchr(variable, '_');
	if (!guid)
		return EFI_INVALID_PARAMETER;
	guid++;
	name = strchr(guid, '_');
	if (!name)
		return EFI_INVALID_PARAMETER;
	name++;
	end = strchr(name, '=');
	if (!end)
		return EFI_INVALID_PARAMETER;

	name_len = end - name;
	if (*variable_name_size < (name_len + 1)) {
		*variable_name_size = name_len + 1;
		return EFI_BUFFER_TOO_SMALL;
	}
	end++; /* point to value */

	/* variable name */
	p = variable_name;
	utf8_utf16_strncpy(&p, name, name_len);
	variable_name[name_len] = 0;
	*variable_name_size = name_len + 1;

	/* guid */
	c = *(name - 1);
	*(name - 1) = '\0'; /* guid need be null-terminated here */
	uuid_str_to_bin(guid, (unsigned char *)vendor, UUID_STR_FORMAT_GUID);
	*(name - 1) = c;

	/* attributes */
	parse_attr(end, attributes);

	return EFI_SUCCESS;
}

/**
 * efi_get_next_variable_name() - enumerate the current variable names
 * @variable_name_size:	size of variable_name buffer in byte
 * @variable_name:	name of uefi variable's name in u16
 * @vendor:		vendor's guid
 *
 * This function implements the GetNextVariableName service.
 *
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details: http://wiki.phoenix.com/wiki/index.php/
 *		EFI_RUNTIME_SERVICES#GetNextVariableName.28.29
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_get_next_variable_name(efi_uintn_t *variable_name_size,
					       u16 *variable_name,
					       const efi_guid_t *vendor)
{
	char *native_name, *variable, *tmp_list, *merged_list;
	ssize_t name_len, list_len;
	char regex[256];
	char * const regexlist[] = {regex};
	u32 attributes;
	int i;
	efi_status_t ret;

	EFI_ENTRY("%p \"%ls\" %pUl", variable_name_size, variable_name, vendor);

	if (!variable_name_size || !variable_name || !vendor)
		return EFI_EXIT(EFI_INVALID_PARAMETER);

	if (variable_name[0]) {
		/* check null-terminated string */
		for (i = 0; i < *variable_name_size; i++)
			if (!variable_name[i])
				break;
		if (i >= *variable_name_size)
			return EFI_EXIT(EFI_INVALID_PARAMETER);

		/* search for the last-returned variable */
		ret = efi_to_native(&native_name, variable_name, vendor);
		if (ret)
			return EFI_EXIT(ret);

		name_len = strlen(native_name);
		for (variable = efi_variables_list; variable && *variable;) {
			if (!strncmp(variable, native_name, name_len) &&
			    variable[name_len] == '=')
				break;

			variable = strchr(variable, '\n');
			if (variable)
				variable++;
		}

		free(native_name);
		if (!(variable && *variable))
			return EFI_EXIT(EFI_INVALID_PARAMETER);

		/* next variable */
		variable = strchr(variable, '\n');
		if (variable)
			variable++;
		if (!(variable && *variable))
			return EFI_EXIT(EFI_NOT_FOUND);
	} else {
		/*
		 *new search: free a list used in the previous search
		 */
		free(efi_variables_list);
		efi_variables_list = NULL;
		efi_cur_variable = NULL;

		snprintf(regex, 256, "efi_.*-.*-.*-.*-.*_.*");
		list_len = hexport_r(&efi_var_htab, '\n',
				     H_MATCH_REGEX | H_MATCH_KEY,
				     &efi_variables_list, 0, 1, regexlist);
		/*
		 * Note: '1' indicates that nothing is matched
		 */
		if (list_len <= 1) {
			free(efi_variables_list);
			efi_variables_list = NULL;
			list_len = hexport_r(&efi_nv_var_htab, '\n',
					     H_MATCH_REGEX | H_MATCH_KEY,
					     &efi_variables_list, 0, 1,
					     regexlist);
		} else {
			tmp_list = NULL;
			list_len = hexport_r(&efi_nv_var_htab, '\n',
					     H_MATCH_REGEX | H_MATCH_KEY,
					     &tmp_list, 0, 1,
					     regexlist);
			if (list_len <= 1) {
				list_len = 2; /* don't care actual number */
			} else {
				/* merge two variables lists */
				merged_list = malloc(strlen(efi_variables_list)
							+ strlen(tmp_list) + 1);
				strcpy(merged_list, efi_variables_list);
				strcat(merged_list, tmp_list);
				free(efi_variables_list);
				free(tmp_list);
				efi_variables_list = merged_list;
			}
		}

		if (list_len <= 1)
			return EFI_EXIT(EFI_NOT_FOUND);

		variable = efi_variables_list;
	}

	ret = parse_uboot_variable(variable, variable_name_size, variable_name,
				   vendor, &attributes);

	return EFI_EXIT(ret);
}

static
efi_status_t EFIAPI efi_set_variable_common(u16 *variable_name,
					    const efi_guid_t *vendor,
					    u32 attributes,
					    efi_uintn_t data_size,
					    const void *data,
					    bool is_non_volatile)
{
	char *native_name = NULL, *val = NULL, *s;
	efi_uintn_t size;
	u32 attr;
	efi_status_t ret = EFI_SUCCESS;

	/* TODO: implement APPEND_WRITE */
	if (!variable_name || !vendor ||
	    (attributes & EFI_VARIABLE_APPEND_WRITE)) {
		ret = EFI_INVALID_PARAMETER;
		goto err;
	}

	ret = efi_to_native(&native_name, variable_name, vendor);
	if (ret)
		goto err;

#define ACCESS_ATTR (EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS)

	/* check if a variable exists */
	size = 0;
	ret = EFI_CALL(efi_get_variable(variable_name, vendor, &attr,
					&size, NULL));
	if (ret == EFI_BUFFER_TOO_SMALL) {
		if ((is_non_volatile && !(attr & EFI_VARIABLE_NON_VOLATILE)) ||
		    (!is_non_volatile && (attr & EFI_VARIABLE_NON_VOLATILE))) {
			ret = EFI_INVALID_PARAMETER;
			goto err;
		}
	}

	/* delete a variable */
	if (data_size == 0 || !(attributes & ACCESS_ATTR)) {
		if (size) {
			if (attr & READ_ONLY) {
				ret = EFI_WRITE_PROTECTED;
				goto err;
			}
			goto out;
		}
		ret = EFI_SUCCESS;
		goto err; /* not error, but nothing to do */
	}

	/* create/modify a variable */
	if (size && attr != attributes) {
		/*
		 * attributes won't be changed
		 * TODO: take care of APPEND_WRITE once supported
		 */
		ret = EFI_INVALID_PARAMETER;
		goto err;
	}

	val = malloc(2 * data_size + strlen("{ro,run,boot,nv}(blob)") + 1);
	if (!val) {
		ret = EFI_OUT_OF_RESOURCES;
		goto err;
	}

	s = val;

	/*
	 * store attributes
	 * TODO: several attributes are not supported
	 */
	attributes &= (EFI_VARIABLE_NON_VOLATILE |
		       EFI_VARIABLE_BOOTSERVICE_ACCESS |
		       EFI_VARIABLE_RUNTIME_ACCESS);
	s += sprintf(s, "{");
	while (attributes) {
		attr = 1 << (ffs(attributes) - 1);

		if (attr == EFI_VARIABLE_NON_VOLATILE)
			s += sprintf(s, "nv");
		else if (attr == EFI_VARIABLE_BOOTSERVICE_ACCESS)
			s += sprintf(s, "boot");
		else if (attr == EFI_VARIABLE_RUNTIME_ACCESS)
			s += sprintf(s, "run");

		attributes &= ~attr;
		if (attributes)
			s += sprintf(s, ",");
	}
	s += sprintf(s, "}");

	/* store payload: */
	s += sprintf(s, "(blob)");
	s = bin2hex(s, data, data_size);
	*s = '\0';

	EFI_PRINT("setting: %s=%s\n", native_name, val);

out:
	ret = EFI_SUCCESS;
	if (env_efi_set(native_name, val, is_non_volatile))
		ret = EFI_DEVICE_ERROR;

err:
	free(native_name);
	free(val);

	return ret;
}

static
efi_status_t EFIAPI efi_set_volatile_variable(u16 *variable_name,
					      const efi_guid_t *vendor,
					      u32 attributes,
					      efi_uintn_t data_size,
					      const void *data)
{
	return efi_set_variable_common(variable_name, vendor, attributes,
				       data_size, data, false);
}

efi_status_t EFIAPI efi_set_nonvolatile_variable(u16 *variable_name,
						 const efi_guid_t *vendor,
						 u32 attributes,
						 efi_uintn_t data_size,
						 const void *data)
{
	efi_status_t ret;

	ret = efi_set_variable_common(variable_name, vendor, attributes,
				      data_size, data, true);
	if (ret == EFI_SUCCESS)
		/* FIXME: what if save failed? */
		if (env_efi_save())
			ret = EFI_DEVICE_ERROR;

	return ret;
}

/**
 * efi_efi_set_variable() - set value of a UEFI variable
 *
 * This function implements the SetVariable runtime service.
 *
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @variable_name:	name of the variable
 * @vendor:		vendor GUID
 * @attributes:		attributes of the variable
 * @data_size:		size of the buffer with the variable value
 * @data:		buffer with the variable value
 * Return:		status code
 */
efi_status_t EFIAPI efi_set_variable(u16 *variable_name,
				     const efi_guid_t *vendor, u32 attributes,
				     efi_uintn_t data_size, const void *data)
{
	efi_status_t ret;

	EFI_ENTRY("\"%ls\" %pUl %x %zu %p", variable_name, vendor, attributes,
		  data_size, data);

	if (attributes & EFI_VARIABLE_NON_VOLATILE)
		ret = efi_set_nonvolatile_variable(variable_name, vendor,
						   attributes,
						   data_size, data);
	else
		ret = efi_set_volatile_variable(variable_name, vendor,
						attributes, data_size, data);

	return EFI_EXIT(ret);
}
