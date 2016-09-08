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

#ifndef __MINICOREDUMPER_H__
#define __MINICOREDUMPER_H__

#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* opaque data types */
struct mcd_dump_data;
typedef struct mcd_dump_data *mcd_dump_data_t;

/*
 * enum mcd_dump_data_flags - Describes how data is handled.
 *
 * @MCD_DATA_PTR_DIRECT: Follow the pointer directly and read data.
 * @MCD_DATA_PTR_INDIRECT: Follow the pointer to another pointer and then
 *                         read data.
 * @MCD_DATA_NODUMP: Do not dump actual data. (Only dump offset/size
 *                   information, if applicable.)
 * @MCD_LENGTH_DIRECT: Read the length directly.
 * @MCD_LENGTH_INDIRECT: Follow a pointer to the length.
 */
enum mcd_dump_data_flags {
	MCD_DATA_PTR_DIRECT	= 1 << 0,
	MCD_DATA_PTR_INDIRECT	= 1 << 1,
	MCD_LENGTH_DIRECT	= 1 << 2,
	MCD_LENGTH_INDIRECT	= 1 << 3,
	MCD_DATA_NODUMP		= 1 << 4,
};

#ifdef __cplusplus
static mcd_dump_data_flags operator|(mcd_dump_data_flags lhs,
				     mcd_dump_data_flags rhs)
{
	return static_cast<mcd_dump_data_flags>(
	    static_cast<int>(lhs) | static_cast<int>(rhs));
}
#endif

#ifdef __GNUC__
#define ATTR_FMT(si, ftc) __attribute__ ((format (scanf, si, ftc)))
#else
#define ATTR_FMT(si, ftc)
#endif

/*
 * mcd_dump_data_register_text - Register text data to be dumped.
 * The data will not be explicitly stored in the core file.
 * Please note that pointers are read directly and the size of the interesting
 * data will be determined using the conversion specifier in @fmt.
 *
 * @ident: A string to identify the text dump later. If not unique, the text
 *         dump is appended to previously registered text dumps with the same
 *         @ident.
 * @dump_scope: Define scope witch needs to be dumped
 * @save_ptr: If non-NULL, will contain a pointer to the registered data dump,
 *            needed if @mcd_dump_data_unregister will be used.
 * @fmt: Format string used to print the data.
 * @...: n pointers to interesting data
 *
 * Returns 0 on success, otherwise errno value of error.
 */
extern int mcd_dump_data_register_text(const char *ident,
				       unsigned long dump_scope,
				       mcd_dump_data_t *save_ptr,
				       const char *fmt, ...)
ATTR_FMT(4, 5);

/*
 * mcd_vdump_data_register_text - Register text data to be dumped.
 * The data will not be explicitly stored in the core file.
 * Please note that pointers are read directly and the size of the interesting
 * data will be determined using the conversion specifier in @fmt.
 *
 * @ident: A string to identify the text dump later. If not unique, the text
 *         dump is appended to previously registered text dumps with the same
 *         @ident.
 * @dump_scope: Define scope witch needs to be dumped
 * @save_ptr: If non-NULL, will contain a pointer to the registered data dump,
 *            needed if @mcd_dump_data_unregister will be used.
 * @fmt: Format string used to print the data.
 * @ap: va_list of pointers to interesting data
 *
 * Returns 0 on success, otherwise errno value of error.
 */
extern int mcd_vdump_data_register_text(const char *ident,
					unsigned long dump_scope,
					mcd_dump_data_t *save_ptr,
					const char *fmt,
					va_list ap)
ATTR_FMT(4, 0);

/*
 * mcd_dump_data_register_bin - Register binary data to be dumped.
 * The data will be explicitly stored in the core file if a NULL value is
 * used for the ident.
 *
 * @ident: A string to identify the binary dump later. Must be unique!
 *         If NULL, data is stored to core file.
 * @dump_scope: Define scope witch needs to be dumped
 * @save_ptr: If non-NULL, will contain a pointer to the registered data dump,
 *            needed if @mcd_dump_data_unregister will be used.
 * @data_ptr: The memory location to read from.
 * @ptr_flags: MCD_DATA_PTR_DIRECT or MCD_DATA_PTR_INDIRECT;
 *             see enum mcd_dump_data_ptr_type
 * @data_size: How much bytes shall be read from @data_ptr
 *
 * Returns 0 on success, otherwise errno value of error.
 */
extern int mcd_dump_data_register_bin(const char *ident,
				      unsigned long dump_scope,
				      mcd_dump_data_t *save_ptr,
				      void *data_ptr,
				      enum mcd_dump_data_flags ptr_flags,
				      size_t data_size);

/*
 * mcd_dump_data_unregister - Unregister previously registered dump data.
 * @dd: mcd_dump_data_t to be unregistered.
 *
 * Returns 0 upon success, otherwise ENOKEY.
 */
extern int mcd_dump_data_unregister(mcd_dump_data_t dd);

#ifdef __cplusplus
}
#endif

#endif /* __MINICOREDUMPER_H__ */
