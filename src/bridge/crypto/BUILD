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
    name = "rsa",
    srcs = ["rsa.cc"],
    hdrs = ["rsa.h"],
    linkopts = ["-lcrypto"],
    deps = [
        "//src/backing",
        "//src/bridge/error",
        "//src/bridge/ex_data_util",
        "//src/bridge/memory_util:openssl_structs",
        "//src/bridge/nid_util",
    ],
)

cc_test(
    name = "rsa_test",
    size = "small",
    srcs = ["rsa_test.cc"],
    deps = [
        ":rsa",
        "//src/bridge/memory_util:openssl_bio",
        "//src/testing_util:mock_crypto_key_handle",
        "//src/testing_util:openssl_assertions",
        "//src/testing_util:test_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)
