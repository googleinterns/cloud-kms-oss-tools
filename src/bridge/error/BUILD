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
    name = "error",
    srcs = ["error.cc"],
    hdrs = ["error.h"],
    linkopts = ["-lcrypto"],
    deps = [
        ":error_strings",
        "//src/backing",
    ],
)

cc_test(
    name = "error_test",
    size = "small",
    srcs = ["error_test.cc"],
    deps = [
        ":error",
        "//src/testing_util:test_matchers",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "error_strings",
    hdrs = ["error_strings.h"],
    deps = [
        "//src/backing",
        "//src/bridge:engine_name",
    ],
)

cc_test(
    name = "error_strings_test",
    size = "small",
    srcs = ["error_strings_test.cc"],
    deps = [
        ":error_strings",
        "@com_google_googletest//:gtest_main",
    ],
)
