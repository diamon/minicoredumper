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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <printf.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "dump_data_private.h"
#include "common.h"

static int print_fmt_token(FILE *ft, struct remote_data_callbacks *cb,
			   const char *fmt_string, int n,
			   struct dump_data_elem *es_ptr, int fmt_offset,
			   int len, int es_index)
{
#define ASPRINTF_CASE(t) \
	ret = asprintf(&d_str, token, *(t)data_ptr); break
#define ASPRINTF_CASE_NORESOLVE(t) \
	ret = asprintf(&d_str, token, (t)data_ptr); break

	int no_directives = 0;
	void *data_ptr = NULL;
	char *d_str = NULL;
	int fmt_type;
	int err = -1;
	char *token;
	int ret;

	if (len == 0)
		return 0;

	if (es_index == -1) {
		/* no directives in this token */
		fmt_type = PA_LAST;
		no_directives = 1;
	} else if (es_index >= n) {
		/* no variable available, write raw text */
		d_str = strndup(fmt_string + fmt_offset, len);
		goto out;
	} else {
		/* token contains 1 directive */

		struct dump_data_elem *elem = &es_ptr[es_index];

		if (elem->u.length < 1) {
			/* bogus variable, write raw text */
			d_str = strndup(fmt_string + fmt_offset, len);
			goto out;
		} else {
			if (cb && cb->setup_data)
				data_ptr = cb->setup_data(elem, cb->cbdata);
			else
				data_ptr = elem->data_ptr;
			if (!data_ptr)
				goto out_err;

			fmt_type = elem->fmt_type;
		}
	}

	token = strndup(fmt_string + fmt_offset, len);
	if (!token)
		goto out_err;

	switch (fmt_type) {
	case PA_INT:
		ASPRINTF_CASE(int *);
	case PA_CHAR:
		ASPRINTF_CASE(char *);
	case PA_STRING:
		ASPRINTF_CASE_NORESOLVE(char *);
	case PA_POINTER:
		ASPRINTF_CASE(void **);
	case PA_FLOAT:
		ASPRINTF_CASE(float *);
	case PA_DOUBLE:
		ASPRINTF_CASE(double *);
	case (PA_INT | PA_FLAG_SHORT):
		ASPRINTF_CASE(short *);
	case (PA_INT | PA_FLAG_LONG):
		ASPRINTF_CASE(long *);
	case (PA_INT | PA_FLAG_LONG_LONG):
		ASPRINTF_CASE(long long *);
	case (PA_DOUBLE | PA_FLAG_LONG_DOUBLE):
		ASPRINTF_CASE(long double *);
	default:
		if (no_directives)
			ret = asprintf(&d_str, token);
		else
			ret = asprintf(&d_str, "%s", token);
		break;
	}

	free(token);

	if (ret < 0)
		goto out_err;
out:
	if (d_str)
		fwrite(d_str, 1, strlen(d_str), ft);

	err = 0;
out_err:
	if (d_str)
		free(d_str);
	if (data_ptr && cb && cb->cleanup_data)
		cb->cleanup_data(data_ptr);

	return err;
#undef ASPRINTF_CASE
}

int dump_data_file_text(struct mcd_dump_data *dd, FILE *file,
			struct remote_data_callbacks *cb)
{
	const char *fmt_string = dd->fmt;
	int es_index;
	int start;
	int len;
	int i;

	if (!fmt_string)
		return EINVAL;

	len = strlen(fmt_string);

	/* we start es_index with -1 because the first token does
	 * not have a directive in it (i.e. no element associated) */
	es_index = -1;

	start = 0;
	for (i = 0; i < len; i++) {
		if (fmt_string[i] == '%' && fmt_string[i + 1] == '%') {
			/* skip escaped '%' */
			i++;

		} else if (fmt_string[i] == '%') {
			/* print token up to this directive */
			print_fmt_token(file, cb, fmt_string, dd->es_n, dd->es,
					start, i - start, es_index);
			es_index++;
			start = i;
		}
	}

	/* print token to the end of format string */
	print_fmt_token(file, cb, fmt_string, dd->es_n, dd->es, start,
			len - start, es_index);

	return 0;
}

int copy_file(const char *dest, const char *src)
{
	unsigned char c;
	struct stat sb;
	FILE *f_dest;
	FILE *f_src;
	int i;

	if (stat(src, &sb) != 0)
		return -1;

	/* non-regular files ignored */
	if ((sb.st_mode & S_IFMT) != S_IFREG)
		return -1;

	f_src = fopen(src, "r");
	if (!f_src)
		return -1;

	f_dest = fopen(dest, "w");
	if (!f_dest) {
		fclose(f_src);
		return -1;
	}

	while (1) {
		i = fgetc(f_src);
		if (i == EOF)
			break;

		c = (unsigned char)i;

		fwrite(&c, 1, 1, f_dest);
	}

	fclose(f_src);
	fclose(f_dest);

	return 0;
}
