// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (C) 2021, Huawei Technologies Co., Ltd */
/* Atomic P-256 platform attestation for the example TA. */

#include <assert.h>
#include <config.h>
#include <crypto/crypto.h>
#include <drivers/tegra/tegra_fuse.h>
#include <kernel/linker.h>
#include <kernel/mutex.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_store.h>
#include <kernel/user_access.h>
#include <kernel/user_mode_ctx.h>
#include <mm/file.h>
#include <pta_attestation.h>
#include "p256_point.h"
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee/entry_std.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <tee/uuid.h>
#include <utee_defines.h>

#ifndef CFG_TEGRA_FUSE
#error "atomic attestation requires CFG_TEGRA_FUSE"
#endif

#define PTA_NAME "attestation.pta"
#define P256_BYTES 32
#define P256_PUBLIC_BYTES 64
#define P256_SIGNATURE_BYTES 64
#define KEY_RECORD_SIZE 120

#define OFF_VERSION 27
#define OFF_TOTAL_LENGTH 29
#define OFF_PURPOSE 33
#define OFF_RESERVED 34
#define OFF_CHALLENGE 36
#define OFF_DEVICE_ID 68
#define OFF_ATTESTATION_KEY_ID 100
#define OFF_RECEIPT_KEY 132
#define OFF_TA_UUID 196
#define OFF_TA_SHDR 212
#define OFF_TA_RUNTIME 244
#define OFF_TEE_RUNTIME 276
#define OFF_ALGORITHM 308
#define OFF_PUBLIC_KEY_LENGTH 310
#define OFF_PUBLIC_KEY 312
#define OFF_SIGNATURE_LENGTH 376
#define OFF_SIGNATURE 378

static const TEE_UUID pta_uuid = PTA_ATTESTATION_UUID;
static const TEE_UUID example_ta_uuid = {
	0xd9f9b15a, 0xbc1c, 0x4d62,
	{ 0x92, 0xa4, 0x61, 0xc4, 0x33, 0x83, 0xd4, 0x73 }
};
static const uint8_t example_ta_uuid_bytes[16] = {
	0xd9, 0xf9, 0xb1, 0x5a, 0xbc, 0x1c, 0x4d, 0x62,
	0x92, 0xa4, 0x61, 0xc4, 0x33, 0x83, 0xd4, 0x73
};
static const uint8_t platform_domain[] = "MFG_PLATFORM_ATTESTATION_V1";
static const uint8_t device_id_domain[] = "MFG_DEVICE_ID_V1";
static const uint8_t attestation_key_domain[] = "MFG_ATTESTATION_KEY_V1";
static const uint8_t key_file_name[] = "jetson_attest_p256_v1";
static const uint8_t key_record_magic[8] = {
	'M', 'F', 'G', 'A', 'P', 'K', '1', 0
};

static const uint8_t p256_order[P256_BYTES] = {
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
	0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
static const uint8_t p256_half_order[P256_BYTES] = {
	0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
	0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
	0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8
};

static struct ecc_keypair *attestation_key;
static struct mutex attestation_mutex = MUTEX_INITIALIZER;

static void put_be16(uint8_t *p, uint16_t value)
{
	p[0] = value >> 8;
	p[1] = value;
}

static void put_be32(uint8_t *p, uint32_t value)
{
	p[0] = value >> 24;
	p[1] = value >> 16;
	p[2] = value >> 8;
	p[3] = value;
}

static bool all_zero(const uint8_t *p, size_t size)
{
	uint8_t acc = 0;

	while (size--)
		acc |= *p++;
	return !acc;
}

static int compare_be32(const uint8_t a[P256_BYTES],
			const uint8_t b[P256_BYTES])
{
	return memcmp(a, b, P256_BYTES);
}

static bool scalar_is_canonical(const uint8_t scalar[P256_BYTES])
{
	return !all_zero(scalar, P256_BYTES) &&
	       compare_be32(scalar, p256_order) < 0;
}

static void normalize_low_s(uint8_t signature[P256_SIGNATURE_BYTES])
{
	uint8_t *s = signature + P256_BYTES;
	uint8_t low[P256_BYTES] = { 0 };
	int borrow = 0;
	int i = 0;

	if (compare_be32(s, p256_half_order) <= 0)
		return;
	for (i = P256_BYTES - 1; i >= 0; i--) {
		int diff = (int)p256_order[i] - (int)s[i] - borrow;

		if (diff < 0) {
			diff += 256;
			borrow = 1;
		} else {
			borrow = 0;
		}
		low[i] = diff;
	}
	memcpy(s, low, sizeof(low));
	memzero_explicit(low, sizeof(low));
}

static TEE_Result hash_parts(const void *a, size_t a_size,
			     const void *b, size_t b_size,
			     const void *c, size_t c_size,
			     uint8_t digest[TEE_SHA256_HASH_SIZE])
{
	void *ctx = NULL;
	TEE_Result res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);

	if (res)
		return res;
	res = crypto_hash_init(ctx);
	if (!res && a_size)
		res = crypto_hash_update(ctx, a, a_size);
	if (!res && b_size)
		res = crypto_hash_update(ctx, b, b_size);
	if (!res && c_size)
		res = crypto_hash_update(ctx, c, c_size);
	if (!res)
		res = crypto_hash_final(ctx, digest, TEE_SHA256_HASH_SIZE);
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result export_bignum_fixed(struct bignum *value,
				      uint8_t out[P256_BYTES])
{
	size_t size = crypto_bignum_num_bytes(value);

	if (!size || size > P256_BYTES)
		return TEE_ERROR_BAD_FORMAT;
	memset(out, 0, P256_BYTES);
	crypto_bignum_bn2bin(value, out + P256_BYTES - size);
	return TEE_SUCCESS;
}

static TEE_Result allocate_key(void)
{
	TEE_Result res = TEE_SUCCESS;

	assert(!attestation_key);
	attestation_key = calloc(1, sizeof(*attestation_key));
	if (!attestation_key)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = crypto_acipher_alloc_ecc_keypair(attestation_key,
					       TEE_TYPE_ECDSA_KEYPAIR, 256);
	if (res) {
		free(attestation_key);
		attestation_key = NULL;
		return res;
	}
	attestation_key->curve = TEE_ECC_CURVE_NIST_P256;
	return TEE_SUCCESS;
}

static void free_key(void)
{
	if (!attestation_key)
		return;
	crypto_bignum_clear(attestation_key->d);
	crypto_bignum_free(&attestation_key->d);
	crypto_bignum_free(&attestation_key->x);
	crypto_bignum_free(&attestation_key->y);
	free(attestation_key);
	attestation_key = NULL;
}

static TEE_Result public_key_is_valid(const uint8_t public_key[P256_PUBLIC_BYTES])
{
	return p256_point_is_valid(public_key) ? TEE_SUCCESS :
						 TEE_ERROR_BAD_FORMAT;
}

static TEE_Result export_public_key(uint8_t public_key[P256_PUBLIC_BYTES])
{
	TEE_Result res = export_bignum_fixed(attestation_key->x, public_key);

	if (!res)
		res = export_bignum_fixed(attestation_key->y,
					  public_key + P256_BYTES);
	return res;
}

static TEE_Result validate_loaded_key(void)
{
	struct ecc_public_key public = { 0 };
	uint8_t material[P256_BYTES * 3] = { 0 };
	uint8_t digest[TEE_SHA256_HASH_SIZE] = { 0 };
	uint8_t signature[P256_SIGNATURE_BYTES] = { 0 };
	size_t signature_size = sizeof(signature);
	TEE_Result res = export_bignum_fixed(attestation_key->d, material);

	if (!res)
		res = export_public_key(material + P256_BYTES);
	if (!res && !scalar_is_canonical(material))
		res = TEE_ERROR_BAD_FORMAT;
	if (!res)
		res = public_key_is_valid(material + P256_BYTES);
	if (res)
		goto out;

	/* A sign/verify self-test proves that persisted d matches persisted x||y. */
	res = hash_parts("MFG_ATTEST_KEY_SELFTEST_V1", 26,
			 NULL, 0, NULL, 0, digest);
	if (!res)
		res = crypto_acipher_ecc_sign(TEE_ALG_ECDSA_P256,
					      attestation_key, digest,
					      sizeof(digest), signature,
					      &signature_size);
	if (res || signature_size != sizeof(signature))
		goto out;
	res = crypto_acipher_alloc_ecc_public_key(&public,
						 TEE_TYPE_ECDSA_PUBLIC_KEY, 256);
	if (res)
		goto out;
	public.curve = TEE_ECC_CURVE_NIST_P256;
	res = crypto_bignum_bin2bn(material + P256_BYTES, P256_BYTES, public.x);
	if (!res)
		res = crypto_bignum_bin2bn(material + P256_BYTES * 2,
					  P256_BYTES, public.y);
	if (!res)
		res = crypto_acipher_ecc_verify(TEE_ALG_ECDSA_P256, &public,
						 digest, sizeof(digest), signature,
						 sizeof(signature));
	crypto_acipher_free_ecc_public_key(&public);
out:
	memzero_explicit(material, sizeof(material));
	memzero_explicit(digest, sizeof(digest));
	memzero_explicit(signature, sizeof(signature));
	return res;
}

static TEE_Result storage_read(uint8_t data[KEY_RECORD_SIZE])
{
	const struct tee_file_operations *fops = NULL;
	struct tee_file_handle *file = NULL;
	struct tee_pobj *object = NULL;
	size_t file_size = 0;
	size_t read_size = KEY_RECORD_SIZE;
	TEE_Result res = TEE_ERROR_BAD_STATE;

	fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
	if (!fops)
		return TEE_ERROR_NOT_IMPLEMENTED;
	res = tee_pobj_get((TEE_UUID *)&pta_uuid, (void *)key_file_name,
			   sizeof(key_file_name) - 1, TEE_DATA_FLAG_ACCESS_READ,
			   TEE_POBJ_USAGE_OPEN, fops, &object);
	if (res)
		return res;
	res = object->fops->open(object, &file_size, &file);
	if (res)
		goto out;
	if (file_size != KEY_RECORD_SIZE) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto close;
	}
	res = object->fops->read(file, 0, data, NULL, &read_size);
	if (!res && read_size != KEY_RECORD_SIZE)
		res = TEE_ERROR_CORRUPT_OBJECT;
close:
	object->fops->close(&file);
out:
	tee_pobj_release(object);
	return res;
}

static TEE_Result storage_create(const uint8_t data[KEY_RECORD_SIZE])
{
	const struct tee_file_operations *fops = NULL;
	struct tee_file_handle *file = NULL;
	struct tee_pobj *object = NULL;
	bool created = false;
	TEE_Result res = TEE_ERROR_BAD_STATE;

	fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
	if (!fops)
		return TEE_ERROR_NOT_IMPLEMENTED;
	res = tee_pobj_get((TEE_UUID *)&pta_uuid, (void *)key_file_name,
			   sizeof(key_file_name) - 1, TEE_DATA_FLAG_ACCESS_WRITE,
			   TEE_POBJ_USAGE_CREATE, fops, &object);
	if (res)
		return res;
	/* Exclusive create: an existing object is never opened or overwritten. */
	res = object->fops->create(object, false, NULL, 0, NULL, 0,
				  NULL, NULL, 0, &file);
	if (!res) {
		created = true;
		res = object->fops->write(file, 0, data, NULL, KEY_RECORD_SIZE);
		object->fops->close(&file);
	}
	if (!res)
		tee_pobj_create_final(object);
	else if (created)
		object->fops->remove(object);
	tee_pobj_release(object);
	return res;
}

static TEE_Result serialize_key(uint8_t record[KEY_RECORD_SIZE])
{
	TEE_Result res = TEE_SUCCESS;

	memset(record, 0, KEY_RECORD_SIZE);
	memcpy(record, key_record_magic, sizeof(key_record_magic));
	put_be16(record + 8, 1);
	put_be16(record + 10, 2);
	put_be16(record + 12, TEE_ECC_CURVE_NIST_P256);
	put_be16(record + 14, P256_BYTES);
	res = export_bignum_fixed(attestation_key->x, record + 24);
	if (!res)
		res = export_bignum_fixed(attestation_key->y, record + 56);
	if (!res)
		res = export_bignum_fixed(attestation_key->d, record + 88);
	return res;
}

static TEE_Result deserialize_key(const uint8_t record[KEY_RECORD_SIZE])
{
	TEE_Result res = TEE_ERROR_CORRUPT_OBJECT;

	if (memcmp(record, key_record_magic, sizeof(key_record_magic)) ||
	    record[8] || record[9] != 1 || record[10] || record[11] != 2 ||
	    record[12] || record[13] != TEE_ECC_CURVE_NIST_P256 ||
	    record[14] || record[15] != P256_BYTES ||
	    !all_zero(record + 16, 8))
		return res;
	res = allocate_key();
	if (res)
		return res;
	res = crypto_bignum_bin2bn(record + 24, P256_BYTES, attestation_key->x);
	if (!res)
		res = crypto_bignum_bin2bn(record + 56, P256_BYTES,
					  attestation_key->y);
	if (!res)
		res = crypto_bignum_bin2bn(record + 88, P256_BYTES,
					  attestation_key->d);
	if (!res)
		res = validate_loaded_key();
	if (res) {
		free_key();
		return TEE_ERROR_CORRUPT_OBJECT;
	}
	return TEE_SUCCESS;
}

static TEE_Result init_key(bool permit_create)
{
	uint8_t record[KEY_RECORD_SIZE] = { 0 };
	TEE_Result res = TEE_SUCCESS;

	if (attestation_key)
		return TEE_SUCCESS;
	res = storage_read(record);
	if (!res)
		res = deserialize_key(record);
	if (res != TEE_ERROR_ITEM_NOT_FOUND || !permit_create)
		goto out;

	res = allocate_key();
	if (!res)
		res = crypto_acipher_gen_ecc_key(attestation_key, 256);
	if (!res)
		res = validate_loaded_key();
	if (!res)
		res = serialize_key(record);
	if (!res)
		res = storage_create(record);
	if (res)
		free_key();
out:
	memzero_explicit(record, sizeof(record));
	return res;
}

static TEE_Result hash_binary(const TEE_UUID *uuid, uint8_t *hash)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	unsigned int tag_len = FILE_TAG_SIZE;
	const struct ts_store_ops *ops = NULL;
	struct ts_store_handle *handle = NULL;

	SCATTERED_ARRAY_FOREACH(ops, ta_stores, struct ts_store_ops) {
		res = ops->open(uuid, &handle);
		if (!res)
			break;
	}
	if (res)
		return res;
	COMPILE_TIME_ASSERT(FILE_TAG_SIZE == TEE_SHA256_HASH_SIZE);
	res = ops->get_tag(handle, hash, &tag_len);
	ops->close(handle);
	return res;
}

static bool is_region_valid(struct vm_region *region)
{
	uint32_t dontwant = VM_FLAG_EPHEMERAL | VM_FLAG_PERMANENT | VM_FLAG_LDELF;

	return (region->flags & VM_FLAG_READONLY) && !(region->flags & dontwant);
}

static int compare_regions(const void *a, const void *b)
{
	const struct vm_region *one = *(const struct vm_region **)a;
	const struct vm_region *two = *(const struct vm_region **)b;

	if (one->size < two->size)
		return -1;
	if (one->size > two->size)
		return 1;
	return memcmp((void *)one->va, (void *)two->va, one->size);
}

static TEE_Result hash_regions(struct vm_info *vm_info, uint8_t *hash)
{
	struct vm_region **regions = NULL;
	struct vm_region *region = NULL;
	size_t count = 0;
	size_t i = 0;
	void *ctx = NULL;
	TEE_Result res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);

	if (res)
		return res;
	res = crypto_hash_init(ctx);
	if (res)
		goto out;
	TAILQ_FOREACH(region, &vm_info->regions, link)
		if (is_region_valid(region))
			count++;
	regions = malloc(count * sizeof(*regions));
	if (!regions) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	TAILQ_FOREACH(region, &vm_info->regions, link)
		if (is_region_valid(region))
			regions[i++] = region;
	enter_user_access();
	qsort(regions, count, sizeof(*regions), compare_regions);
	for (i = 0; i < count; i++) {
		region = regions[i];
		res = crypto_hash_update(ctx, (uint8_t *)region->va, region->size);
		if (res)
			break;
	}
	exit_user_access();
	if (!res)
		res = crypto_hash_final(ctx, hash, TEE_SHA256_HASH_SIZE);
out:
	free(regions);
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result hash_calling_ta_memory(uint8_t hash[TEE_SHA256_HASH_SIZE])
{
	struct ts_session *calling = ts_get_calling_session();
	struct user_mode_ctx *context = NULL;
	struct ts_session *current = NULL;
	TEE_Result res = TEE_ERROR_ACCESS_DENIED;

	if (!calling || !calling->ctx || !is_user_ta_ctx(calling->ctx))
		return res;
	context = to_user_mode_ctx(calling->ctx);
	if (!context)
		return res;
	current = ts_pop_current_session();
	res = hash_regions(&context->vm_info, hash);
	ts_push_current_session(current);
	return res;
}

static TEE_Result hash_tee_memory(uint8_t hash[TEE_SHA256_HASH_SIZE])
{
	void *ctx = NULL;
	TEE_Result res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);

	if (res)
		return res;
	res = crypto_hash_init(ctx);
	if (!res)
		res = crypto_hash_update(ctx, __text_start,
					 __text_data_start - __text_start);
	if (!res)
		res = crypto_hash_update(ctx, __text_data_end,
					 __text_end - __text_data_end);
	if (!res && IS_ENABLED(CFG_WITH_PAGER))
		res = crypto_hash_update(ctx, __text_init_start,
					 __text_init_end - __text_init_start);
	if (!res && IS_ENABLED(CFG_WITH_PAGER))
		res = crypto_hash_update(ctx, __text_pageable_start,
					 __text_pageable_end - __text_pageable_start);
	if (!res)
		res = crypto_hash_update(ctx, __rodata_start,
					 __rodata_end - __rodata_start);
	if (!res && IS_ENABLED(CFG_WITH_PAGER))
		res = crypto_hash_update(ctx, __rodata_init_start,
					 __rodata_init_end - __rodata_init_start);
	if (!res && IS_ENABLED(CFG_WITH_PAGER))
		res = crypto_hash_update(ctx, __rodata_pageable_start,
					 __rodata_pageable_end - __rodata_pageable_start);
	if (!res)
		res = crypto_hash_final(ctx, hash, TEE_SHA256_HASH_SIZE);
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result derive_device_id(uint8_t device_id[TEE_SHA256_HASH_SIZE])
{
	fuse_ecid_t *ecid = tegra_fuse_get_ecid();
	uint8_t canonical_ecid[16] = { 0 };
	uint8_t framing[3] = { 2, 0, 16 };
	TEE_Result res = TEE_ERROR_NO_DATA;

	if (!ecid)
		return res;
	put_be32(canonical_ecid, ecid->ecid[3]);
	put_be32(canonical_ecid + 4, ecid->ecid[2]);
	put_be32(canonical_ecid + 8, ecid->ecid[1]);
	put_be32(canonical_ecid + 12, ecid->ecid[0]);
	res = hash_parts(device_id_domain, sizeof(device_id_domain) - 1,
			 framing, sizeof(framing), canonical_ecid,
			 sizeof(canonical_ecid), device_id);
	memzero_explicit(canonical_ecid, sizeof(canonical_ecid));
	return res;
}

static TEE_Result derive_attestation_key_id(
		const uint8_t public_key[P256_PUBLIC_BYTES],
		uint8_t key_id[TEE_SHA256_HASH_SIZE])
{
	const uint8_t framing[4] = { 0, 2, 0, P256_PUBLIC_BYTES };

	return hash_parts(attestation_key_domain,
			  sizeof(attestation_key_domain) - 1,
			  framing, sizeof(framing), public_key,
			  P256_PUBLIC_BYTES, key_id);
}

static TEE_Result build_and_sign(uint32_t purpose, const uint8_t *challenge,
				 const uint8_t *receipt_key, uint8_t *evidence)
{
	uint8_t public_key[P256_PUBLIC_BYTES] = { 0 };
	uint8_t digest[TEE_SHA256_HASH_SIZE] = { 0 };
	size_t signature_size = P256_SIGNATURE_BYTES;
	TEE_Result res = init_key(purpose == PTA_ATTESTATION_PURPOSE_ENROLLMENT);

	if (res)
		goto out;
	res = export_public_key(public_key);
	if (res)
		goto out;
	memset(evidence, 0, PTA_ATTESTATION_EVIDENCE_SIZE);
	memcpy(evidence, platform_domain, sizeof(platform_domain) - 1);
	put_be16(evidence + OFF_VERSION, 1);
	put_be32(evidence + OFF_TOTAL_LENGTH, PTA_ATTESTATION_TRANSCRIPT_SIZE);
	evidence[OFF_PURPOSE] = purpose;
	memcpy(evidence + OFF_CHALLENGE, challenge, PTA_ATTESTATION_CHALLENGE_SIZE);
	res = derive_device_id(evidence + OFF_DEVICE_ID);
	if (!res)
		res = derive_attestation_key_id(public_key,
						evidence + OFF_ATTESTATION_KEY_ID);
	if (res)
		goto out;
	memcpy(evidence + OFF_RECEIPT_KEY, receipt_key,
	       PTA_ATTESTATION_RECEIPT_KEY_SIZE);
	memcpy(evidence + OFF_TA_UUID, example_ta_uuid_bytes,
	       sizeof(example_ta_uuid_bytes));
	res = hash_binary(&example_ta_uuid, evidence + OFF_TA_SHDR);
	if (!res)
		res = hash_calling_ta_memory(evidence + OFF_TA_RUNTIME);
	if (!res)
		res = hash_tee_memory(evidence + OFF_TEE_RUNTIME);
	if (!res)
		res = hash_parts(evidence, PTA_ATTESTATION_TRANSCRIPT_SIZE,
				 NULL, 0, NULL, 0, digest);
	if (res)
		goto out;
	put_be16(evidence + OFF_ALGORITHM, 2);
	put_be16(evidence + OFF_PUBLIC_KEY_LENGTH, P256_PUBLIC_BYTES);
	memcpy(evidence + OFF_PUBLIC_KEY, public_key, P256_PUBLIC_BYTES);
	put_be16(evidence + OFF_SIGNATURE_LENGTH, P256_SIGNATURE_BYTES);
	res = crypto_acipher_ecc_sign(TEE_ALG_ECDSA_P256, attestation_key,
				      digest, sizeof(digest),
				      evidence + OFF_SIGNATURE,
				      &signature_size);
	if (!res && signature_size != P256_SIGNATURE_BYTES)
		res = TEE_ERROR_BAD_FORMAT;
	if (!res)
		normalize_low_s(evidence + OFF_SIGNATURE);
out:
	memzero_explicit(public_key, sizeof(public_key));
	memzero_explicit(digest, sizeof(digest));
	if (res)
		memset(evidence, 0, PTA_ATTESTATION_EVIDENCE_SIZE);
	return res;
}

static TEE_Result cmd_get_platform_evidence(uint32_t param_types,
					     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					    TEE_PARAM_TYPE_MEMREF_INPUT,
					    TEE_PARAM_TYPE_MEMREF_INPUT,
					    TEE_PARAM_TYPE_MEMREF_OUTPUT);
	uint32_t purpose = params[0].value.a;
	uint8_t *challenge = params[1].memref.buffer;
	uint8_t *receipt_key = params[2].memref.buffer;
	uint8_t *evidence = params[3].memref.buffer;
	size_t evidence_size = params[3].memref.size;
	TEE_Result res = TEE_SUCCESS;

	if (param_types != expected || params[0].value.b ||
	    (purpose != PTA_ATTESTATION_PURPOSE_ENROLLMENT &&
	     purpose != PTA_ATTESTATION_PURPOSE_REGISTRATION &&
	     purpose != PTA_ATTESTATION_PURPOSE_OPENING) ||
	    params[1].memref.size != PTA_ATTESTATION_CHALLENGE_SIZE ||
	    params[2].memref.size != PTA_ATTESTATION_RECEIPT_KEY_SIZE ||
	    !challenge || !receipt_key || (!evidence && evidence_size))
		return TEE_ERROR_BAD_PARAMETERS;
	params[3].memref.size = PTA_ATTESTATION_EVIDENCE_SIZE;
	if (evidence_size < PTA_ATTESTATION_EVIDENCE_SIZE)
		return TEE_ERROR_SHORT_BUFFER;
	if (all_zero(challenge, PTA_ATTESTATION_CHALLENGE_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;
	res = public_key_is_valid(receipt_key);
	if (res)
		return res;
	mutex_lock(&attestation_mutex);
	res = build_and_sign(purpose, challenge, receipt_key, evidence);
	mutex_unlock(&attestation_mutex);
	return res;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **session_context __unused)
{
	struct ts_session *calling = ts_get_calling_session();

	if (!calling || !calling->ctx || !is_user_ta_ctx(calling->ctx) ||
	    memcmp(&calling->ctx->uuid, &example_ta_uuid,
		   sizeof(example_ta_uuid)))
		return TEE_ERROR_ACCESS_DENIED;
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t command, uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Param bounce[TEE_NUM_PARAMS] = { 0 };
	TEE_Param *effective = NULL;
	TEE_Result copy_res = TEE_ERROR_GENERIC;
	TEE_Result res = to_bounce_params(param_types, params, bounce, &effective);

	if (res)
		return res;
	if (command == PTA_ATTESTATION_GET_PLATFORM_EVIDENCE)
		res = cmd_get_platform_evidence(param_types, effective);
	else
		res = TEE_ERROR_NOT_SUPPORTED;
	copy_res = from_bounce_params(param_types, params, bounce, effective);
	if (!res && copy_res)
		res = copy_res;
	return res;
}

pseudo_ta_register(.uuid = PTA_ATTESTATION_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
