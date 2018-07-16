/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __DUMP_DATA_PRIVATE_H__
#define __DUMP_DATA_PRIVATE_H__

/*
 * DUMP_DATA_VERSION 1:
 *     MCD_TEXT:PA_STRING => (char **)
 *
 * DUMP_DATA_VERSION 2:
 *     MCD_TEXT:PA_STRING => (char *)
 */
#define DUMP_DATA_VERSION 2

enum dump_type {
	MCD_BIN = 0,
	MCD_TEXT = 1,
};

struct dump_data_elem {
	void		*data_ptr;
	unsigned long	flags;
	union {
		size_t	*length_ptr;
		size_t	length;
	} u;
	int		fmt_type;
};

struct mcd_dump_data {
	enum dump_type type;
	char *ident;
	unsigned long dump_scope;
	struct dump_data_elem *es;	/* array of data elements */
	unsigned int es_n;		/* count of array elements */

	/* only for text dumps */
	char *fmt;

	struct mcd_dump_data *next;	/* next item in linked list */
};

#endif /* __DUMP_DATA_PRIVATE_H__ */
