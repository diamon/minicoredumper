/*
 * Copyright (c) 2012-2015 Ericsson AB
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

#ifndef INCLUDE_COMMON_DEFS_H
#define INCLUDE_COMMON_DEFS_H

/* Well-known name for this service. */
#define VALUE_SERVICE_NAME "org.ericsson.mcd"

/* Object path to the provided object. */
#define VALUE_SERVICE_OBJECT_PATH "/GlobalValue"

/* Interface */
#define VALUE_SERVICE_INTERFACE	"org.ericsson.mcd"

#define SIGNAL_DUMP		"dump"
#define SIGNAL_DUMP_MCD_DONE	"dump_mcd_done"
#define SIGNAL_DUMP_APP_DONE	"dump_app_done"
#define SIGNAL_REGISTER		"register"

#define STATE_D_RUN		1
#define STATE_D_DUMP		2
#define STATE_D_DONE		3
#define STATE_D_DUMP_DONE	4


#define STATE_APPS_IDLE		1
#define STATE_APPS_REGISTERED	1
#define STATE_APPS_UNREGISTERED	2
#define STATE_APPS_DUMP		3
#define STATE_APPS_DUMP_DONE	4

#define STATE_MCD_NOTDEF	5
#define STATE_MCD_CRASHED	6
#define STATE_MCD_DUMP_DONE	7

#endif
