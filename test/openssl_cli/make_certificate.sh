#!/bin/bash
#
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Checks that the OpenSSL CLI is able to dynamically load the engine without
# error. Success when exit code of script is 0.

set -eu

CLOUD_KMS_KEY_RESOURCE_ID="projects/cloud-kms-oss-tools/locations/global/keyRings/test-key-ring/cryptoKeys/test-key/cryptoKeyVersions/1"

# Passed from Bazel `args` on sh_test target.
LIBENGINE_REL_PATH="${1}"

# OpenSSL requires the path to the engine to be absolute.
LIBENGINE_ABS_PATH="$(realpath "${LIBENGINE_REL_PATH}")"

openssl req -engine "${LIBENGINE_ABS_PATH}" -new -x509 -text \
            -days 365 \
            -key "${CLOUD_KMS_KEY_RESOURCE_ID}" \
            -keyform engine \
            -out certificate.pem
