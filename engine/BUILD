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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

cc_binary(
    name = "engine.so",
    srcs = ["main.cc"],
    linkshared = 1,
    linkstatic = 1,
    linkopts = ["-lcrypto"],
    deps = [":rand"],
)

cc_library(
    name = "wrapper",
    srcs = ["wrapper.cc"],
    hdrs = ["wrapper.h"],
    deps = [":rand"],
)

cc_library(
    name = "rand",
    srcs = ["rand.cc"],
    hdrs = ["rand.h"],
)

cc_test(
    name = "rand_test",
    srcs = ["rand_test.cc"],
    deps = [
        ":rand",
        "@gtest",
        "@gtest//:gtest_main",
    ],
)

cc_test(
    name = "engine_test",
    srcs = ["engine_test.cc"],
    linkopts = ["-lcrypto"],
    deps = [
        ":engine.so",
        "@gtest",
        "@gtest//:gtest_main",
    ],
)
