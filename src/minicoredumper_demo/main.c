/*
 * Copyright (c) 2012-2018 Linutronix GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "minicoredumper.h"

int __attribute__((optimize("O0"))) main(int argc, char *argv[])
{
	char *str1 = "This is string 1.";
	unsigned long val1 = 0x1abc123f;
	unsigned long val2 = 0x2abc123e;
	mcd_dump_data_t dd[9];
	unsigned long *val3;
	size_t sizeof_val2;
	char *str2;
	size_t s;

	/* setup malloc'd string */
	str2 = strdup("This is string 2.");

	/* setup indirect length for val2 */
	sizeof_val2 = sizeof(val2);

	/* setup indirect pointer for val3 */
	val3 = malloc(sizeof(*val3));
	if (!val3)
		return 1;
	*val3 = 0x3abc123d;

#if (__SIZEOF_LONG__ == 8)
	/* fill the rest for 64-bit types */
	val1 |= (unsigned long)0x4abc123c << 32;
	val2 |= (unsigned long)0x5abc123b << 32;
	*val3 |= (unsigned long)0x6abc123a << 32;
#endif

	/* register text dumps */
	/* "This is string 1.\n" */
	mcd_dump_data_register_text("tdump1.txt", 6, &dd[0],
				    "%s\n", str1);
	/* "This is string 2.\n" */
	mcd_dump_data_register_text("tdump2.txt", 6, &dd[1],
				    "%s\n", str2);
	/* "val1: %lx=0x0 %x=0x0 %hx=0x0 %hhx=0x0\n" */
	mcd_dump_data_register_text("tdump3.txt", 6, &dd[2],
				    "val1: %%lx=0x%lx", &val1);
	mcd_dump_data_register_text("tdump3.txt", 6, &dd[3],
				    " %%x=0x%x", (int*) &val1);
	mcd_dump_data_register_text("tdump3.txt", 6, &dd[4],
				    " %%hx=0x%hx", (short*) &val1);
	mcd_dump_data_register_text("tdump3.txt", 6, &dd[5],
				    " %%hhx=0x%hhx\n", (char *) &val1);
	/* "val1=0x0 val2=0x0 val3=0x0\n" */
	mcd_dump_data_register_text("tdump4.txt", 6, &dd[6],
				    "val1=0x%lx val2=0x%lx "
				    "val3=0x%lx\n",
				    &val1, &val2, val3);

	/* register binary dumps */
	mcd_dump_data_register_bin(NULL, 6, &dd[7], &val2,
				   (size_t)&sizeof_val2,
				   MCD_DATA_PTR_DIRECT | MCD_LENGTH_INDIRECT);
	mcd_dump_data_register_bin("val3.bin", 6, &dd[8], &val3, sizeof(val3),
				   MCD_DATA_PTR_INDIRECT | MCD_LENGTH_DIRECT);

	/* print values for reference */
	printf("str1: val=%s ptr=%p ind_ptr=%p\n", str1, str1, &str1);
	printf("str2: val=%s ptr=%p ind_ptr=%p\n", str2, str2, &str2);
	printf("val1: val=0x%lx ptr=%p\n", val1, &val1);
	printf("val2: val=0x%lx ptr=%p\n", val2, &val2);
	printf("val3: val=0x%lx ptr=%p ind_ptr=%p\n", *val3, val3, &val3);

	/* either crash or wait specified seconds */
	if (argc == 1) {
		/* crash */
		char *p = NULL;
		printf("\nno program args, crashing...\n\n");
		printf("crash: %c\n", *p);
	} else {
		int i;

		i = atoi(argv[1]);
		if (i < 1)
			i = 1;

		for ( ; i > 0; i--) {
			printf("waiting (%d)...\n", i);
			sleep(1);
		}
	}

	/* unregister dumps */
	for (s = 0; s < (sizeof(dd) / sizeof(dd[0])); s++)
		mcd_dump_data_unregister(dd[s]);

	/* cleanup */
	free(str2);
	free(val3);

	printf("graceful exit\n");

	return 0;
}
