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

# This test validates various properties about how Bazel targets in the
# project should interact with each other.

set -eu

# Make sure that there is no path from any of the backing layer targets to the
# bridge layer targets.
test "$(bazel query 'somepath(deps("//src/backing"), "//src/bridge/...")' | \
        wc -l)" -eq 0 || exit 1

# Make sure that no dependencies in the backing layer have -lcrypto in their
# linkopts.
test "$(bazel query 'attr(linkopts, "\[-lcrypto\]", deps("//src/backing"))' | \
        wc -l)" -eq 0 || exit 1
