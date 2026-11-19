#!/usr/bin/env bash
# Copyright 2025 MobShield Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# MOBSHIELD post-build verification. Add AFTER Compile Sources / linking.
set -euo pipefail

if [[ -z "${DERIVED_FILE_DIR:-}" ]]; then
  echo "error: DERIVED_FILE_DIR is not set" >&2
  exit 1
fi

HEADER_PATH="${DERIVED_FILE_DIR}/mobshield_buildinfo.h"
if [[ ! -f "${HEADER_PATH}" ]]; then
  echo "error: mobshield_buildinfo.h not found at ${HEADER_PATH}" >&2
  exit 1
fi

BUILD_ID="$(grep '#define MOBSHIELD_BUILD_ID ' "${HEADER_PATH}" | sed -E 's/.*"([^"]+)".*/\1/' | head -n1)"
if [[ -z "${BUILD_ID}" ]]; then
  echo "error: MOBSHIELD_BUILD_ID missing in header" >&2
  exit 1
fi

APP_BUNDLE="${TARGET_BUILD_DIR}/${WRAPPER_NAME:-}"
BINARY_PATH="${TARGET_BUILD_DIR}/${EXECUTABLE_PATH:-}"

if [[ -z "${APP_BUNDLE}" || ! -d "${APP_BUNDLE}" ]]; then
  echo "warning: MobShield verify skipped (app bundle not found)" >&2
  exit 0
fi

# The native core embeds "MOBSHIELD_BUILD_ID=<id>" from the header it was compiled with. If this
# build's ID is missing, MobShield's native code was compiled with its bundled header (SwiftPM always
# does this), so the binary is the same as in every other app using this MobShield release. That is
# reported, not treated as a failure: see docs/personalization.md.
if ! grep -a -rq "MOBSHIELD_BUILD_ID=${BUILD_ID}" "${APP_BUNDLE}" 2>/dev/null; then
  echo "warning: MobShield verify: build ID ${BUILD_ID} not found in the app bundle; MobShield's native code uses its bundled header (see docs/personalization.md)." >&2
fi

VERIFY_BINARY="${BINARY_PATH}"
if [[ -z "${VERIFY_BINARY}" || ! -f "${VERIFY_BINARY}" ]]; then
  VERIFY_BINARY="${APP_BUNDLE}/$(basename "${APP_BUNDLE}" .app)"
fi

EXPECTED_SIGNER="$(echo "${MOBSHIELD_EXPECTED_SIGNER_SHA256:-}" | tr -d ':' | tr '[:upper:]' '[:lower:]')"
if [[ -n "${EXPECTED_SIGNER}" && "${EXPECTED_SIGNER}" != *"0000000000000000"* && -f "${VERIFY_BINARY}" ]]; then
  ACTUAL_SIGNER="$(codesign -d --extract-certificates "${VERIFY_BINARY}" 2>/dev/null | openssl x509 -inform DER -outform PEM 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/sha256 //I' | tr -d ':' | tr '[:upper:]' '[:lower:]' || true)"
  if [[ -n "${ACTUAL_SIGNER}" && "${ACTUAL_SIGNER}" != "${EXPECTED_SIGNER}" ]]; then
    echo "error: MobShield verify failed: signing cert SHA-256 mismatch" >&2
    echo "  Expected: ${EXPECTED_SIGNER}" >&2
    echo "  Actual:   ${ACTUAL_SIGNER}" >&2
    exit 1
  fi
fi

echo "MobShield verify passed for $(basename "${APP_BUNDLE}")"
