/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

int invalid_ident(const char *ident)
{
	if (!ident)
		return 0;

	if (strcmp(ident, "") == 0)
		return 1;

	if (strcmp(ident, ".") == 0)
		return 1;

	if (strcmp(ident, "..") == 0)
		return 1;

	if (strchr(ident, '/'))
		return 1;

	return 0;
}
