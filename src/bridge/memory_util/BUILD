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
    name = "openssl_structs",
    hdrs = ["openssl_structs.h"],
    linkopts = ["-lcrypto"],
)

cc_test(
    name = "openssl_structs_test",
    size = "small",
    srcs = ["openssl_structs_test.cc"],
    deps = [
        ":openssl_structs",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "openssl_bio",
    srcs = ["openssl_bio.cc"],
    hdrs = ["openssl_bio.h"],
    linkopts = ["-lcrypto"],
    deps = [
        ":openssl_structs",
        "//src/backing",
        "//src/testing_util:openssl_assertions",
        "//src/testing_util:test_matchers",
    ],
)

cc_test(
    name = "openssl_bio_test",
    size = "small",
    srcs = ["openssl_bio_test.cc"],
    deps = [
        ":openssl_bio",
        "@com_google_googletest//:gtest_main",
    ],
)
