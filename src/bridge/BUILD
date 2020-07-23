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

package(default_visibility = ["//src:__subpackages__"])

cc_library(
    name = "bridge",
    srcs = ["main.c"],
    linkopts = ["-lcrypto"],
    deps = ["//src/bridge:engine_bind"],
)

cc_library(
    name = "engine_bind",
    srcs = ["engine_bind.cc"],
    hdrs = ["engine_bind.h"],
    linkopts = ["-lcrypto"],
    deps = [
        ":engine_name",
        ":engine_setup",
        "//src/backing",
        "//src/bridge/error",
        "//src/bridge/ex_data_util",
    ],
)

cc_test(
    name = "engine_bind_test",
    size = "small",
    srcs = ["engine_bind_test.cc"],
    # Statically link in libcrypto in test environment only to avoid symbol
    # issues with BoringSSL which only appear in the test environment.
    linkstatic = True,
    linkopts = ["-l:libcrypto.a", "-ldl"],
    deps = [
        ":engine_bind",
        "//src/testing_util:openssl_assertions",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "engine_name",
    hdrs = ["engine_name.h"],
)

cc_library(
    name = "engine_setup",
    srcs = ["engine_setup.cc"],
    hdrs = ["engine_setup.h"],
    linkopts = ["-lcrypto"],
    deps = [
        "//src/backing",
        "//src/bridge/error",
        "//src/bridge/ex_data_util",
        "//src/bridge/ex_data_util:engine_data",
        "//src/bridge/rsa",
    ],
)
