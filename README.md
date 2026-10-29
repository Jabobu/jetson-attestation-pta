# Jetson attestation PTA

This repository contains an OP-TEE pseudo trusted application (PTA) for Jetson
Orin (T234) and a small example client. The PTA returns one P-256 signed
attestation response for a challenge. It accepts calls only from the example
trusted application (TA), UUID `d9f9b15a-bc1c-4d62-92a4-61c43383d473`.
The TA creates and stores its receipt key in OP-TEE secure storage. The normal
world client requests evidence and writes the response to a file.

This is an extracted adaptation. It has not been tested on hardware. It
replaces the original attestation PTA ABI; software that uses the original PTA
commands will not work with this replacement.

## Evidence and trust

The 442-byte response contains a 308-byte signed transcript, the attestation
public key, and a low-s P-256 signature. The transcript binds a purpose, a
32-byte challenge, an ECID-derived device pseudonym, the receipt public key,
the fixed caller UUID, and three measurements. These measurements cover the
authenticated TA-store tag, selected read-only caller memory, and OP-TEE code
and read-only data. They do not measure the entire platform or boot chain. The
pseudonym is deterministic and linkable; it does not provide anonymity.

A verifier must trust an attestation public key enrolled through an independent
trusted process. It must check a fresh challenge, purpose, caller UUID, and all
measurements against its policy. A signature alone does not establish device
provenance. Generate an unpredictable, nonzero challenge for each request.
Track and atomically consume each challenge once. Secure storage rollback
protection depends on the platform configuration.

The PTA creates its attestation key only for an enrollment request. Registration
and opening require that key to exist. The example verifier checks a previously
trusted key and expected values; it does not establish trust on first use or
track challenge state.

## Prerequisites

Use Jetson Linux 36.5 for T234. Download the Driver Package (BSP), Driver
Package (BSP) Sources, and Bootlin toolchain from the [NVIDIA release page](https://developer.nvidia.com/embedded/jetson-linux-r365).
Extract `public_sources.tbz2`, then extract
`Linux_for_Tegra/source/nvidia-jetson-optee-source.tbz2`. NVIDIA documents this
layout and the required OP-TEE build dependencies in its [OP-TEE guide](https://docs.nvidia.com/jetson/archives/r36.5/DeveloperGuide/SD/Security/OpTee.html)
and in `atf_and_optee_README.txt` from the source package. The BSP provides
the T234 Standalone MM image needed to package a TOS image. The OP-TEE tree
uses NVIDIA's separately licensed T234 crypto prebuilt. Obtain it with the
source package and follow its license terms.

The overlay checks these two pristine files before it replaces them:

```text
63d1e9d1c13909599000c03a13544f3643aefd3b78241b0ac6c4b010b906ac1c  core/pta/attestation.c
97ca42ee44dfc21c94b00917f5c126aecee5f9bb4e9dd8e8a8751b32206325e6  lib/libutee/include/pta_attestation.h
```

These hashes identify those two files only. They do not identify the rest of
the source package. The overlay also adds `core/pta/p256_point.h`; it refuses
to overwrite an existing file there. Use a clean copy of the source package
for the build.

## Integrate and build

Set `OPTEE_OS` to the extracted `optee/optee_os` directory. Apply the overlay:

```sh
./scripts/apply-overlay.sh --apply "$OPTEE_OS"
```

Check the installed files:

```sh
./scripts/apply-overlay.sh --check "$OPTEE_OS"
```

Run this core compile and link check. Set `BUILD_DIR` to a new absolute
output directory and `CROSS_COMPILE` to the Bootlin AArch64 compiler prefix:

```sh
make -C "$OPTEE_OS" PLATFORM=tegra PLATFORM_FLAVOR=t234 \
  CROSS_COMPILE64="$CROSS_COMPILE" \
  NV_CCC_PREBUILT="$OPTEE_OS/prebuilt/t234/libcommon_crypto.a" \
  CFG_ATTESTATION_PTA=y CFG_JETSON_FTPM_HELPER_PTA=n \
  O="$BUILD_DIR" -j4
```

This check produces `core/tee.elf`, `core/tee-raw.bin`, and
`export-ta_arm64` under `BUILD_DIR`. It does not produce a complete Jetson TOS
image. The NVIDIA wrapper adds Standalone MM and early TAs to its final build.
It also enables the fTPM helper by default. Disabling the helper removes fTPM
functionality. A complete helper-disabled TOS build, packaging, and installation
have not been validated for this adaptation. Select and validate a compatible
BSP and fTPM configuration before deployment.

Build the example with the TA development kit and client library from the
matching OP-TEE build. Set `CROSS_COMPILE` to the Bootlin AArch64 compiler
prefix and use an absolute output directory:

```sh
make -C example \
  TA_DEV_KIT_DIR="$BUILD_DIR/export-ta_arm64" \
  OPTEE_CLIENT_EXPORT=/path/to/optee/install/t234/usr \
  CROSS_COMPILE=/path/to/toolchain/bin/aarch64-buildroot-linux-gnu- \
  O=/absolute/path/to/example-output
```

The TA is `example-output/ta/d9f9b15a-bc1c-4d62-92a4-61c43383d473.ta`.
The client is `example-output/host/attestation_example`. The TA must be signed
with a key trusted by the installed OP-TEE. The build system's default signing
key is for development. Provision the corresponding expected measurements.

A device run requires a separately validated TOS image containing this PTA.
Install the TA under `/lib/optee_armtz` and the client under `/usr/sbin` on
the device. Start the matching `tee-supplicant` service. The example requires
working OP-TEE secure storage.

## Request and verify evidence

On the verifier, generate a fresh 32-byte challenge and record it as hex. Send
it to the device with the expected purpose. For example, on the device:

```sh
attestation_example enrollment "$CHALLENGE_HEX" evidence.bin
```

Use `registration` or `opening` for later purposes. Transfer the 442-byte
`evidence.bin` to the verifier. On a system with Node.js 16.9 or later, verify it:

```sh
node example/verify.mjs evidence.bin enrollment "$CHALLENGE_HEX" \
  "$TRUSTED_ATTESTATION_PUBKEY_HEX" "$DEVICE_ID_HEX" \
  "$TA_SIGNED_HEADER_MEASUREMENT_HEX" "$TA_RUNTIME_MEASUREMENT_HEX" \
  "$TEE_RUNTIME_MEASUREMENT_HEX"
```

Supply the key and expected values from trusted enrollment or provisioning,
not from the evidence under test. The trusted public key is 64 bytes of hex
encoded P-256 `x || y`. The challenge, device ID, and each measurement are 32
bytes of hex. The verifier uses Node's built-in crypto and has no package
dependencies. Atomically consume the outstanding challenge as part of
verification. Reject replays.

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE). The NVIDIA source package and
build dependencies are distributed separately under their own terms.

## Source check

Run the point validation test on a build host with Python 3, the Python
`cryptography` package, and a C compiler:

```sh
python3 tests/test_p256_point.py
```
