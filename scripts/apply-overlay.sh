#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Install/check the example-specific replacement in a matching OP-TEE tree.
set -eu

usage() {
    echo "usage: $0 --apply|--check /path/to/optee_os" >&2
    exit 2
}
[ "$#" -eq 2 ] || usage
mode=$1
tree=$2
case "$mode" in --apply|--check) ;; *) usage ;; esac
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
core=$tree/core/pta/attestation.c
header=$tree/lib/libutee/include/pta_attestation.h
point_header=$tree/core/pta/p256_point.h
[ -f "$core" ] && [ -f "$header" ] || {
    echo "missing OP-TEE core or header in $tree" >&2
    exit 1
}
if [ "$mode" = --apply ]; then
    # Both files must be pristine before either is changed. These identify the
    # original files, not the revision of the rest of the BSP source tree.
    [ "$(sha256sum "$core" | awk '{print $1}')" = 63d1e9d1c13909599000c03a13544f3643aefd3b78241b0ac6c4b010b906ac1c ] &&
    [ "$(sha256sum "$header" | awk '{print $1}')" = 97ca42ee44dfc21c94b00917f5c126aecee5f9bb4e9dd8e8a8751b32206325e6 ] || {
        echo "refusing to replace non-baseline OP-TEE sources" >&2
        exit 1
    }
    [ ! -e "$point_header" ] || {
        echo "refusing to overwrite $point_header" >&2
        exit 1
    }
    install -m 0644 "$repo/pta/attestation.c" "$core"
    install -m 0644 "$repo/pta/pta_attestation.h" "$header"
    install -m 0644 "$repo/pta/p256_point.h" "$point_header"
fi
cmp -s "$repo/pta/attestation.c" "$core" &&
cmp -s "$repo/pta/pta_attestation.h" "$header" &&
cmp -s "$repo/pta/p256_point.h" "$point_header" || {
    echo "attestation overlay does not match this repository" >&2
    exit 1
}
echo "attestation overlay verified"
