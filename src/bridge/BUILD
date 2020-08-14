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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(default_visibility = ["//src/bridge:__subpackages__"])

cc_binary(
    name = "libengine.so",
    srcs = [
        "main.c",
    ],
    linkopts = ["-lcrypto"],
    linkshared = 1,
    linkstatic = 1,
    visibility = ["//test:__subpackages__"],
    deps = [
        "//src/bridge:engine_bind",
        "//src/bridge:engine_name",
        "//src/bridge/error",
        "//src/bridge/error:error_strings",
        "//src/bridge/ex_data_util",
        "//src/bridge/ex_data_util:engine_data",
        "//src/bridge/memory_util:openssl_bio",
        "//src/bridge/memory_util:openssl_structs",
        "//src/bridge/nid_util",
    ],
)

cc_library(
    name = "engine_bind",
    srcs = ["engine_bind.cc"],
    hdrs = ["engine_bind.h"],
    linkopts = ["-lcrypto"],
    deps = [
        ":engine_name",
        "//src/backing",
        "//src/bridge/crypto:rsa",
        "//src/bridge/error",
        "//src/bridge/ex_data_util",
        "//src/bridge/ex_data_util:engine_data",
        "//src/bridge/key_loader",
    ],
)

cc_test(
    name = "engine_bind_test",
    size = "small",
    srcs = ["engine_bind_test.cc"],
    deps = [
        ":engine_bind",
        "//src/bridge/memory_util:openssl_structs",
        "//src/testing_util:mock_client",
        "//src/testing_util:mock_crypto_key_handle",
        "//src/testing_util:openssl_assertions",
        "//src/testing_util:test_matchers",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "engine_name",
    hdrs = ["engine_name.h"],
)
