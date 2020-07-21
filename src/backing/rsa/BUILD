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
        "kms_rsa_key.h",
        "rsa_key.h",
    ],
)

filegroup(
    name = "sources",
    srcs = glob(
        [
            "**/*.h",
            "**/*.cc",
        ],
        allow_empty = False,
        exclude = ["**/*_test.cc"],
    ),
)

cc_library(
    name = "kms_rsa_key",
    srcs = ["kms_rsa_key.cc"],
    hdrs = ["kms_rsa_key.h"],
    deps = [
        ":rsa_key",
        "//src/backing/client",
        "//src/backing/client:digest_case",
        "//src/backing/client:public_key",
        "//src/backing/status",
        "//src/backing/status:status_or",
    ],
)

cc_test(
    name = "kms_rsa_key_test",
    size = "small",
    srcs = ["kms_rsa_key_test.cc"],
    deps = [
        ":kms_rsa_key",
        "//src/testing_util:mock_client",
        "//src/testing_util:test_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "rsa_key",
    hdrs = ["rsa_key.h"],
    deps = [
        "//src/backing/client:digest_case",
        "//src/backing/client:public_key",
        "//src/backing/status",
        "//src/backing/status:status_or",
    ],
)
