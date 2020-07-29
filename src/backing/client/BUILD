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
        "client.h",
        "client_factory.h",
        "crypto_key_version_algorithm.h",
        "digest_case.h",
        "public_key.h",
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
    ) + [
        "//src/backing/client/grpc_client:sources",
    ],
)

cc_library(
    name = "client_factory",
    srcs = ["client_factory.cc"],
    hdrs = ["client_factory.h"],
    deps = [
        ":client",
        "//src/backing:base",
        "//src/backing/client/grpc_client",
        "//src/backing/status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
    ],
)

cc_test(
    name = "client_factory_test",
    size = "small",
    srcs = ["client_factory_test.cc"],
    deps = [
        "//src/backing",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "client",
    hdrs = ["client.h"],
    deps = [
        ":digest_case",
        ":public_key",
        "//src/backing:base",
        "//src/backing/status",
        "//src/backing/status:status_or",
    ],
)

cc_library(
    name = "digest_case",
    hdrs = ["digest_case.h"],
    srcs = ["digest_case.cc"],
    deps = [
        "//src/backing:base",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "digest_case_test",
    size = "small",
    srcs = ["digest_case_test.cc"],
    deps = [
        ":digest_case",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "public_key",
    hdrs = ["public_key.h"],
    deps = [
        ":crypto_key_version_algorithm",
        "//src/backing:base",
    ],
)

cc_test(
    name = "public_key_test",
    size = "small",
    srcs = ["public_key_test.cc"],
    deps = [
        ":public_key",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "crypto_key_version_algorithm",
    srcs = ["crypto_key_version_algorithm.cc"],
    hdrs = ["crypto_key_version_algorithm.h"],
    deps = [
        "//src/backing:base",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "crypto_key_version_algorithm_test",
    size = "small",
    srcs = ["crypto_key_version_algorithm_test.cc"],
    deps = [
        ":crypto_key_version_algorithm",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "clock",
    hdrs = ["clock.h"],
)

cc_test(
    name = "clock_test",
    size = "small",
    srcs = ["clock_test.cc"],
    deps = [
        ":clock",
        "@com_google_googletest//:gtest_main",
    ],
)
