/*
 * Copyright (c) 2012-2016 Ericsson AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __DUMP_DATA_PRIVATE_H__
#define __DUMP_DATA_PRIVATE_H__

#include <stdbool.h>

/*
 * DUMP_DATA_VERSION 1:
 *     MCD_TEXT:PA_STRING => (char **)
 *
 * DUMP_DATA_VERSION 2:
 *     MCD_TEXT:PA_STRING => (char *)
 */
#define DUMP_DATA_VERSION 2

#define DUMP_DATA_MONITOR_ENV "MINICOREDUMPER_MONITOR"

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
