/*
 * Copyright (c) Nutanix 2023. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __TAR_H__
#define __TAR_H__

/* The size of a tar block */
#define BLOCK_SIZE 512

/* Structs for gnu tar format */
struct sparse {
    char offset[12];
    char numbytes[12];
};

struct tar_header {
    char name[100];              // 0-99
    char mode[8];                // 100-107
    char uid[8];                 // 108-115
    char gid[8];                 // 116-123
    char numbytes[12];           // 124-135
    char mtime[12];              // 136-147
    char checksum[8];            // 148-155
    char type;                   // 156
    char linkname[100];          // 157-256
    char magic[6];               // 257-262
    char version[2];             // 263-264
    char username[32];           // 265-296
    char groupname[32];          // 297-328
    char dev_major[8];           // 329-336
    char dev_minor[8];           // 337-344
    char atime[12];              // 345-356
    char ctime[12];              // 357-368
    char multivolume_offset[12]; // 369-380
    char longnames[4];           // 381-384
    char pad0;                   // 385
    struct sparse sparse_map[4]; // 386-481
    char is_extended;            // 482
    char filesize[12];           // 483-494
    char pad1[17];               // 495-511
};


/* Structs for posix tar format */
struct posix_header {
    char name[100];     // 0-99
    char mode[8];       // 100-107
    char uid[8];        // 108-115
    char gid[8];        // 116-123
    char numbytes[12];  // 124-135
    char mtime[12];     // 136-147
    char checksum[8];   // 148-155
    char type;          // 156
    char linkname[100]; // 157-256
    char magic[6];      // 257-262
    char version[2];    // 263-264
    char username[32];  // 265-296
    char groupname[32]; // 297-328
    char dev_major[8];  // 329-336
    char dev_minor[8];  // 337-344
    char prefix[155];   // 345-499
    char pad[12];       // 500-511
};

struct posix_sparse_list_element {
    off64_t offset;
    off64_t num_bytes;
    struct posix_sparse_list_element *next_element;
};

struct posix_sparse_list {
    unsigned long int list_length;
    struct posix_sparse_list_element *first_element;
};

#endif