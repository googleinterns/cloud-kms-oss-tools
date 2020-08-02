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
    name = "key_loader",
    srcs = ["key_loader.cc"],
    hdrs = ["key_loader.h"],
    linkopts = ["-lcrypto"],
    deps = [
        ":ec_key_loader",
        ":rsa_key_loader",
        "//src/backing",
        "//src/bridge/error",
        "//src/bridge/ex_data_util",
        "//src/bridge/memory_util:openssl_structs",
    ],
)

cc_test(
    name = "key_loader_test",
    size = "small",
    srcs = ["key_loader_test.cc"],
    deps = [
        ":key_loader",
        "//src/bridge/rsa",
        "//src/testing_util:mock_client",
        "//src/testing_util:openssl_assertions",
        "//src/testing_util:test_matchers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ec_key_loader",
    srcs = ["ec_key_loader.cc"],
    hdrs = ["ec_key_loader.h"],
    linkopts = ["-lcrypto"],
    deps = [
        "//src/backing",
        "//src/bridge/ex_data_util",
        "//src/bridge/memory_util:openssl_structs",
    ],
)

cc_test(
    name = "ec_key_loader_test",
    size = "small",
    srcs = ["ec_key_loader_test.cc"],
    deps = [
        ":ec_key_loader",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "rsa_key_loader",
    srcs = ["rsa_key_loader.cc"],
    hdrs = ["rsa_key_loader.h"],
    linkopts = ["-lcrypto"],
    deps = [
        "//src/backing",
        "//src/bridge/ex_data_util",
        "//src/bridge/memory_util:openssl_structs",
    ],
)

cc_test(
    name = "rsa_key_loader_test",
    size = "small",
    srcs = ["rsa_key_loader_test.cc"],
    deps = [
        ":rsa_key_loader",
        "@com_google_googletest//:gtest_main",
    ],
)
