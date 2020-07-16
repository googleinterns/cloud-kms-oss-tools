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

package(default_visibility = ["//src/backing:__subpackages__"])

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
    name = "key_management_service_stub",
    srcs = ["key_management_service_stub.cc"],
    hdrs = ["key_management_service_stub.h"],
    deps = [
        ":proto_util",
        "//src/backing/status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_grpc",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
    ],
)

cc_test(
    name = "key_management_service_stub_test",
    size = "small",
    srcs = ["key_management_service_stub_test.cc"],
    deps = [
        ":key_management_service_stub",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "client_context_factory",
    srcs = ["client_context_factory.cc"],
    hdrs = ["client_context_factory.h"],
    deps = [
        "//src/backing/client:clock",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
    ],
)

cc_test(
    name = "client_context_factory_test",
    size = "small",
    srcs = ["client_context_factory_test.cc"],
    deps = [
        ":client_context_factory",
        "//src/backing/client/testing_util:fake_clock",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "proto_util",
    srcs = ["proto_util.cc"],
    hdrs = ["proto_util.h"],
    deps = [
        "//src/backing/client:crypto_key_version_algorithm",
        "//src/backing/client:digest_case",
        "//src/backing/status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/strings",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
    ],
)

cc_test(
    name = "proto_util_test",
    size = "small",
    srcs = ["proto_util_test.cc"],
    deps = [
        ":proto_util",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)
