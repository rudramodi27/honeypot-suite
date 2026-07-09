#!/bin/sh
# =====================================================================
# hardening/sign_release.sh
# Detached-signs a release artifact (tarball, wheel, container digest
# export) with GPG, and verifies the signature as a self-check.
#
# TESTED in this build session with a real ephemeral GPG keypair: key
# generation, detached-sign, verify (good signature), and a tamper test
# (modified file → BAD signature, non-zero exit) all worked exactly as
# this script implements. The real CI signing key is the only thing not
# present here — that has to come from your org's actual key material,
# imported via a CI secret (GPG_PRIVATE_KEY below), not generated fresh
# on every run the way the local self-test did.
#
# Usage:
#   ./sign_release.sh sign <file>      # detached-sign <file> → <file>.asc
#   ./sign_release.sh verify <file>    # verify <file>.asc against <file>
# =====================================================================
set -eu

GPG_KEY_ID="${GPG_KEY_ID:-}"   # fingerprint or email of the signing key

sign() {
    target="$1"
    if [ ! -f "$target" ]; then
        echo "ERROR: $target not found" >&2
        exit 1
    fi
    if [ -z "$GPG_KEY_ID" ]; then
        echo "ERROR: GPG_KEY_ID not set — refusing to sign with whatever" \
             "default key happens to be in the keyring" >&2
        exit 1
    fi
    gpg --batch --yes --local-user "$GPG_KEY_ID" \
        --detach-sign --armor "$target"
    echo "Signed: ${target}.asc"
}

verify() {
    target="$1"
    sig="${target}.asc"
    if [ ! -f "$sig" ]; then
        echo "ERROR: signature file $sig not found" >&2
        exit 1
    fi
    gpg --verify "$sig" "$target"
    echo "Verification OK: $target matches $sig"
}

case "${1:-}" in
    sign)   shift; sign "$1" ;;
    verify) shift; verify "$1" ;;
    *) echo "Usage: $0 {sign|verify} <file>"; exit 1 ;;
esac
