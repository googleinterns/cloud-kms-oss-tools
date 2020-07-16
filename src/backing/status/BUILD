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

# Headers that are safe to export to the bridge layer.
filegroup(
    name = "bridge_headers",
    srcs = [
        "status.h",
        "status_or.h",
    ],
)

filegroup(
    name = "sources",
    srcs = [
        "status.cc",
        "status.h",
        "status_or.h",
    ],
)

cc_library(
    name = "status_or",
    hdrs = ["status_or.h"],
    deps = [
        ":status",
    ],
)

cc_test(
    name = "status_or_test",
    size = "small",
    srcs = ["status_or_test.cc"],
    deps = [
        ":status_or",
        "//src/testing_util:test_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "status",
    srcs = ["status.cc"],
    hdrs = ["status.h"],
)

cc_test(
    name = "status_test",
    size = "small",
    srcs = ["status_test.cc"],
    deps = [
        ":status",
        "@com_google_googletest//:gtest_main",
    ],
)
