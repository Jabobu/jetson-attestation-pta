/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdint.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <attestation_example.h>
#include <pta_attestation.h>

static const TEE_UUID pta_uuid = PTA_ATTESTATION_UUID;
static const char key_id[] = "example-receipt-p256-v1";

/* OP-TEE exports bignums with their leading zero bytes omitted. */
static TEE_Result public_coordinate(TEE_ObjectHandle key, uint32_t attribute,
				    uint8_t out[32])
{
	uint8_t encoded[32] = { 0 };
	size_t len = sizeof(encoded);
	TEE_Result res = TEE_GetObjectBufferAttribute(key, attribute, encoded, &len);

	if (res != TEE_SUCCESS)
		return res;
	if (len > sizeof(encoded))
		return TEE_ERROR_BAD_FORMAT;
	memset(out, 0, 32);
	memcpy(out + 32 - len, encoded, len);
	return TEE_SUCCESS;
}

/* Persist the key object itself; never export the private component. A storage
 * failure other than absence must not silently replace the enrolled key. */
static TEE_Result receipt_public_key(uint8_t pub[64])
{
	TEE_ObjectHandle key = TEE_HANDLE_NULL, transient = TEE_HANDLE_NULL;
	TEE_Attribute curve;
	TEE_Result res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_id,
				       sizeof(key_id) - 1, TEE_DATA_FLAG_ACCESS_READ, &key);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &transient);
		if (res != TEE_SUCCESS) goto out;
		TEE_InitValueAttribute(&curve, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
		res = TEE_GenerateKey(transient, 256, &curve, 1);
		if (res != TEE_SUCCESS) goto out;
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, key_id,
				 sizeof(key_id) - 1, TEE_DATA_FLAG_ACCESS_READ,
				 transient, NULL, 0, &key);
	}
	if (res != TEE_SUCCESS) goto out;
	res = public_coordinate(key, TEE_ATTR_ECC_PUBLIC_VALUE_X, pub);
	if (res == TEE_SUCCESS)
		res = public_coordinate(key, TEE_ATTR_ECC_PUBLIC_VALUE_Y, pub + 32);
out:
	if (key != TEE_HANDLE_NULL) TEE_CloseObject(key);
	if (transient != TEE_HANDLE_NULL) TEE_FreeTransientObject(transient);
	return res;
}

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) { }
TEE_Result TA_OpenSessionEntryPoint(uint32_t types, TEE_Param p[4], void **ctx)
{
	(void)p; (void)ctx;
	return types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS;
}
void TA_CloseSessionEntryPoint(void *ctx) { (void)ctx; }
TEE_Result TA_InvokeCommandEntryPoint(void *ctx, uint32_t cmd, uint32_t types, TEE_Param p[4])
{
	TEE_TASessionHandle session = TEE_HANDLE_NULL;
	TEE_Param args[4] = { 0 };
	uint8_t pub[64] = { 0 }, challenge[32], evidence[EXAMPLE_EVIDENCE_SIZE] = { 0 };
	uint8_t nonzero = 0;
	uint32_t origin = 0;
	TEE_Result res;
	size_t i;
	(void)ctx;
	if (cmd != EXAMPLE_GET_EVIDENCE || types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE) ||
	    p[0].value.a < 1 || p[0].value.a > 3 || p[0].value.b != 0 ||
	    p[1].memref.size != sizeof(challenge) || !p[1].memref.buffer ||
	    !p[2].memref.buffer) return TEE_ERROR_BAD_PARAMETERS;
	if (p[2].memref.size < sizeof(evidence)) {
		p[2].memref.size = sizeof(evidence);
		return TEE_ERROR_SHORT_BUFFER;
	}
	/* Copy the untrusted input before validation and use. */
	memcpy(challenge, p[1].memref.buffer, sizeof(challenge));
	for (i = 0; i < sizeof(challenge); i++) nonzero |= challenge[i];
	if (!nonzero) return TEE_ERROR_BAD_PARAMETERS;
	res = receipt_public_key(pub);
	if (res != TEE_SUCCESS) goto out;
	res = TEE_OpenTASession(&pta_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &session, &origin);
	if (res != TEE_SUCCESS) goto out;
	args[0].value.a = p[0].value.a;
	args[1].memref.buffer = challenge; args[1].memref.size = sizeof(challenge);
	args[2].memref.buffer = pub; args[2].memref.size = sizeof(pub);
	args[3].memref.buffer = evidence; args[3].memref.size = sizeof(evidence);
	res = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE,
		PTA_ATTESTATION_GET_PLATFORM_EVIDENCE,
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT), args, &origin);
	if (res == TEE_SUCCESS && args[3].memref.size != sizeof(evidence)) res = TEE_ERROR_BAD_FORMAT;
	if (res == TEE_SUCCESS) {
		memcpy(p[2].memref.buffer, evidence, sizeof(evidence));
		p[2].memref.size = sizeof(evidence);
	}
out:
	if (session != TEE_HANDLE_NULL) TEE_CloseTASession(session);
	memset(pub, 0, sizeof(pub));
	memset(evidence, 0, sizeof(evidence));
	return res;
}
