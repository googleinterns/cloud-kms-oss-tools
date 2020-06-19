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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

cc_binary(
    name = "libengine.so",
    srcs = ["main.c", "wrapper.h", "wrapper.cc", "engine.cc", "engine.h"],
    linkshared = 1,
    linkstatic = 0,
    linkopts = ["-lcrypto"],
    deps = [":libkms"],
    visibility = ["//visibility:public"],
)

cc_import(
    name = "libkms",
    hdrs = ["rand.h"],
    shared_library = ":libkms.so",
)

cc_binary(
    name = "libkms.so",  # _Needs_ to be prefixed with "lib" and suffixed with ".so".
    srcs = [
        "rand.cc",
        "rand.h"
    ],
    linkshared = 1,
    deps = [
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_grpc",
        "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
    ],
)

# cc_library(
#     name = "rand",
#     srcs = ["rand.cc"],
#     hdrs = ["rand.h"],
#     deps = [
#         "@com_github_grpc_grpc//:grpc++",
#         "@com_google_googleapis//google/cloud/kms/v1:kms_cc_grpc",
#         "@com_google_googleapis//google/cloud/kms/v1:kms_cc_proto",
#     ],
# )

# cc_test(
#     name = "rand_test",
#     srcs = ["rand_test.cc"],
#     deps = [
#         ":rand",
#         "@com_google_googletest//:gtest_main",
#     ],
# )

# Builds OpenSSL. Include ":openssl" as a dependency to a target where the -lcrypto
# linker flag would otherwise be necessary. See https://stackoverflow.com/a/58106111
# # for reference.
# configure_make(
#     name = "openssl",
#     configure_command = "config",
#     configure_options = [
#         "no-shared",
#     ],
#     lib_source = "@openssl//:all",
#     static_libraries = [
#         "libssl.a",
#         "libcrypto.a",
#     ],
# )
