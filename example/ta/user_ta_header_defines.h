/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H
#include <attestation_example.h>
#define TA_UUID EXAMPLE_TA_UUID
#define TA_FLAGS TA_FLAG_SINGLE_INSTANCE
#define TA_STACK_SIZE (4 * 1024)
#define TA_DATA_SIZE (32 * 1024)
#endif
