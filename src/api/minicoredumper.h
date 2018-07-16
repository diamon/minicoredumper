/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
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
 * enum mcd_dump_data_flags - Describes how data and length are handled.
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
 * @dump_scope: Assigns a scope value to this text dump.
 * @save_ptr: If non-NULL, will contain a pointer to the registered data dump,
 *            needed if @mcd_dump_data_unregister will be used.
 * @fmt: Format string used to print the data.
 * @...: The pointers to the interesting data.
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
 * @dump_scope: Assigns a scope value to this text dump.
 * @save_ptr: If non-NULL, will contain a pointer to the registered data dump,
 *            needed if @mcd_dump_data_unregister will be used.
 * @fmt: Format string used to print the data.
 * @ap: va_list of pointers to the interesting data.
 *
 * Returns 0 on success, otherwise errno value of error.
 */
extern int mcd_vdump_data_register_text(const char *ident,
					unsigned long dump_scope,
					mcd_dump_data_t *save_ptr,
					const char *fmt, va_list ap)
ATTR_FMT(4, 0);

/*
 * mcd_dump_data_register_bin - Register binary data to be dumped.
 * The data will be explicitly stored in the core file if a NULL value is
 * used for the ident.
 *
 * @ident: A string to identify the binary dump later. Must be unique!
 *         If NULL, data is stored to core file.
 * @dump_scope: Assigns a scope value to this text dump.
 * @save_ptr: If non-NULL, will contain a pointer to the registered data dump,
 *            needed if @mcd_dump_data_unregister will be used.
 * @data_ptr: The memory location to read from.
 * @data_size: How much bytes shall be read from @data_ptr
 * @flags: See enum mcd_dump_data_flags for types.
 *
 * Returns 0 on success, otherwise errno value of error.
 */
extern int mcd_dump_data_register_bin(const char *ident,
				      unsigned long dump_scope,
				      mcd_dump_data_t *save_ptr,
				      void *data_ptr, size_t data_size,
				      enum mcd_dump_data_flags flags);

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
