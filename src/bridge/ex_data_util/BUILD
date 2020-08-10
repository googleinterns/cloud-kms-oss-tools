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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//src/bridge:__subpackages__"])

cc_library(
    name = "ex_data_util",
    srcs = ["ex_data_util.cc"],
    hdrs = ["ex_data_util.h"],
    linkopts = ["-lcrypto"],
    deps = [
        ":engine_data",
        "//src/backing",
    ],
)

cc_test(
    name = "ex_data_util_test",
    size = "small",
    srcs = ["ex_data_util_test.cc"],
    # TODO(zesp): Remove when https://github.com/googleinterns/cloud-kms-oss-tools/pull/84/
    # is merged in.
    linkstatic = True,
    linkopts = ["-l:libcrypto.a", "-ldl"],
    deps = [
        ":ex_data_util",
        "//src/bridge/memory_util:openssl_structs",
        "//src/testing_util:mock_client",
        "//src/testing_util:mock_crypto_key_handle",
        "//src/testing_util:test_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "engine_data",
    hdrs = ["engine_data.h"],
    linkopts = ["-lcrypto"],
    deps = [
        "//src/backing",
        "//src/bridge/memory_util:openssl_structs",
    ],
)

cc_test(
    name = "engine_data_test",
    size = "small",
    srcs = ["engine_data_test.cc"],
    deps = [
        ":engine_data",
        "//src/testing_util:mock_client",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)
