/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (C) 2021, Huawei Technologies Co., Ltd */
/* Atomic platform-attestation PTA ABI. */
#ifndef __PTA_ATTESTATION_H
#define __PTA_ATTESTATION_H

#define PTA_ATTESTATION_UUID { 0x39800861, 0x182a, 0x4720, \
		{ 0x9b, 0x67, 0x2b, 0xcd, 0x62, 0x2b, 0xc0, 0xb5 } }

#define PTA_ATTESTATION_PURPOSE_ENROLLMENT   1
#define PTA_ATTESTATION_PURPOSE_REGISTRATION 2
#define PTA_ATTESTATION_PURPOSE_OPENING      3

#define PTA_ATTESTATION_CHALLENGE_SIZE 32
#define PTA_ATTESTATION_RECEIPT_KEY_SIZE 64
#define PTA_ATTESTATION_TRANSCRIPT_SIZE 308
#define PTA_ATTESTATION_EVIDENCE_SIZE 442

/*
 * Construct and sign one canonical PlatformAttestationV1 transcript.
 * Only the fixed example TA may open this PTA.
 *
 * [in]  value[0].a  purpose enum above; value[0].b must be zero
 * [in]  memref[1]   exact 32-byte purpose-specific challenge
 * [in]  memref[2]   exact 64-byte example TA receipt key x || y
 * [out] memref[3]   exact 442-byte evidence envelope
 */
#define PTA_ATTESTATION_GET_PLATFORM_EVIDENCE 0x0

#endif /* __PTA_ATTESTATION_H */
