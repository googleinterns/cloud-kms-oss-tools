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
    name = "mock_key_management_service_stub",
    hdrs = ["mock_key_management_service_stub.h"],
    deps = [
        "//src/backing/client/grpc_client:key_management_service_stub",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "mock_client_context_factory",
    hdrs = ["mock_client_context_factory.h"],
    deps = [
        "//src/backing/client/grpc_client:client_context_factory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "test_matchers",
    srcs = ["test_matchers.cc"],
    hdrs = ["test_matchers.h"],
    deps = [
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "test_matchers_test",
    size = "small",
    srcs = ["test_matchers_test.cc"],
    deps = [
        ":test_matchers",
        "//src/backing",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)
