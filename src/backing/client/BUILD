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
    name = "grpc_client",
    srcs = ["grpc_client.cc"],
    hdrs = ["grpc_client.h"],
    deps = [
        ":client",
        ":grpc_client_options",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_grpc",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
        "@com_github_googleapis_google_cloud_cpp//google/cloud:google_cloud_cpp_common",
    ],
)

cc_test(
    name = "grpc_client_test",
    size = "small",
    srcs = ["grpc_client_test.cc"],
    deps = [
        ":grpc_client",
        "//src/backing/client/testing_util:is_proto_equal",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "grpc_client_options",
    hdrs = ["grpc_client_options.h"],
    srcs = ["grpc_client_options.cc"],
    deps = [
        ":grpc_client_default_options",
        "@com_github_grpc_grpc//:grpc++",
    ]
)

cc_test(
    name = "grpc_client_options_test",
    size = "small",
    srcs = ["grpc_client_options_test.cc"],
    deps = [
        ":grpc_client_options",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "grpc_client_default_options",
    hdrs = ["grpc_client_default_options.h"],
)

cc_library(
    name = "client",
    hdrs = ["client.h"],
    deps = [
        ":asymmetric_sign_request",
        ":asymmetric_sign_response",
    ],
)

cc_library(
    name = "asymmetric_sign_request",
    hdrs = ["asymmetric_sign_request.h"],
    deps = [":digest"],
)

cc_test(
    name = "asymmetric_sign_request_test",
    size = "small",
    srcs = ["asymmetric_sign_request_test.cc"],
    deps = [
        ":asymmetric_sign_request",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "asymmetric_sign_response",
    hdrs = ["asymmetric_sign_response.h"],
)

cc_test(
    name = "asymmetric_sign_response_test",
    size = "small",
    srcs = ["asymmetric_sign_response_test.cc"],
    deps = [
        ":asymmetric_sign_response",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "digest",
    hdrs = ["digest.h"],
    deps = [":digest_type"],
)

cc_test(
    name = "digest_test",
    size = "small",
    srcs = ["digest_test.cc"],
    deps = [
        ":digest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "digest_type",
    hdrs = ["digest_type.h"],
)

cc_test(
    name = "digest_type_test",
    size = "small",
    srcs = ["digest_type_test.cc"],
    deps = [
        ":digest_type",
        "@com_google_googleapis//:googleapis_system_includes",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)
