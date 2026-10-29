/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include <attestation_example.h>

static int unhex(const char *s, uint8_t *out, size_t n)
{
	size_t i;
	if (strlen(s) != 2 * n) return -1;
	for (i = 0; i < n; i++) {
		char a = s[2*i], b = s[2*i+1];
		int x = a >= '0' && a <= '9' ? a-'0' : a >= 'a' && a <= 'f' ? a-'a'+10 : a >= 'A' && a <= 'F' ? a-'A'+10 : -1;
		int y = b >= '0' && b <= '9' ? b-'0' : b >= 'a' && b <= 'f' ? b-'a'+10 : b >= 'A' && b <= 'F' ? b-'A'+10 : -1;
		if (x < 0 || y < 0) return -1;
		out[i] = (uint8_t)((x << 4) | y);
	}
	return 0;
}
int main(int argc, char **argv)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = EXAMPLE_TA_UUID;
	TEEC_Operation op = { 0 };
	TEEC_Result res;
	uint32_t origin = 0, purpose = 0;
	uint8_t challenge[EXAMPLE_CHALLENGE_SIZE], evidence[EXAMPLE_EVIDENCE_SIZE], nonzero = 0;
	FILE *f;
	size_t i;
	if (argc != 4) { fprintf(stderr, "usage: %s enrollment|registration|opening CHALLENGE_HEX OUTPUT.bin\n", argv[0]); return 2; }
	if (!strcmp(argv[1], "enrollment")) purpose = 1;
	else if (!strcmp(argv[1], "registration")) purpose = 2;
	else if (!strcmp(argv[1], "opening")) purpose = 3;
	if (!purpose || unhex(argv[2], challenge, sizeof(challenge))) { fprintf(stderr, "invalid purpose or challenge\n"); return 2; }
	for (i = 0; i < sizeof(challenge); i++) nonzero |= challenge[i];
	if (!nonzero) { fprintf(stderr, "challenge must be nonzero\n"); return 2; }
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) { fprintf(stderr, "TEEC_InitializeContext: 0x%08x\n", res); return 1; }
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) { fprintf(stderr, "TEEC_OpenSession: 0x%08x origin %u\n", res, origin); TEEC_FinalizeContext(&ctx); return 1; }
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].value.a = purpose;
	op.params[1].tmpref.buffer = challenge; op.params[1].tmpref.size = sizeof(challenge);
	op.params[2].tmpref.buffer = evidence; op.params[2].tmpref.size = sizeof(evidence);
	res = TEEC_InvokeCommand(&sess, EXAMPLE_GET_EVIDENCE, &op, &origin);
	TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx);
	if (res != TEEC_SUCCESS || op.params[2].tmpref.size != sizeof(evidence)) { fprintf(stderr, "evidence failed: 0x%08x origin %u\n", res, origin); return 1; }
	f = fopen(argv[3], "wb");
	if (!f) { perror("output"); return 1; }
	if (fwrite(evidence, 1, sizeof(evidence), f) != sizeof(evidence)) { perror("write"); fclose(f); remove(argv[3]); return 1; }
	if (fclose(f)) { perror("close"); remove(argv[3]); return 1; }
	return 0;
}
