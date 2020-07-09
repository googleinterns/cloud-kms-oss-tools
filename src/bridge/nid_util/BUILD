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
    name = "nid_util",
    hdrs = ["nid_util.h"],
    srcs = ["nid_util.cc"],
    linkopts = ["-lcrypto"],
    deps = [
        "//src/backing/client:digest_case",
        "//src/backing/status:status",
        "//src/backing/status:status_or",
    ],
)

cc_test(
    name = "nid_util_test",
    size = "small",
    srcs = ["nid_util_test.cc"],
    deps = [
        ":nid_util",
        "//src/testing_util:test_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)
