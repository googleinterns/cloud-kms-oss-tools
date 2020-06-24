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

cc_library(
    name = "status_or",
    hdrs = ["status_or.h"],
    deps = [
        ":status_code",
        ":status",
    ],
)

cc_test(
    name = "status_or_test",
    srcs = ["status_or_test.cc"],
    deps = [
        ":status_or",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)

cc_library(
    name = "status",
    srcs = ["status.cc"],
    hdrs = ["status.h"],
    deps = [":status_code"],
)

cc_test(
    name = "status_test",
    srcs = ["status_test.cc"],
    deps = [
        ":status",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)

cc_library(
    name = "status_code",
    hdrs = ["status_code.h"],
    deps = ["@com_google_absl//absl/status"],
)
