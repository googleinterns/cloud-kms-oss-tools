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

load("@rules_cc//cc:defs.bzl", "cc_import", "cc_library")
load("//:bazel/cc_binary_with_global_copts.bzl", "cc_binary")

package(default_visibility = ["//src:__subpackages__"])

cc_import(
    name = "backing",
    hdrs = [":bridge_headers"],
    shared_library = ":libkms.so",
)

cc_binary(
    name = "libkms.so",
    srcs = [
        "//src/backing/client:sources",
        "//src/backing/crypto_key_handle:sources",
        "//src/backing/status:sources",
    ],
    # `global_copts` is an attribute defined by the `cc_binary` macro from
    # `cc_binary_with_global_copts.bzl`. These "global compiler options" are
    # used to compile the entire `libkms.so` shared object with
    # "-fvisibility=hidden", including dependencies.
    #
    # This custom version of `cc_binary` is used in lieu of the native Starlark
    # `cc_binary` rule since the native `cc_binary` rule's `copts` attribute
    # does not propogate compiler flags to the dependencies of the rule.
    #
    # By compiling all dependencies of the rule with "-fvisibility=hidden",
    # we ensure that only the symbols explicitly allowlisted with the
    # `KMSENGINE_EXPORT` macro are visible to the bridge layer. This needs
    # to be done to avoid symbol conflicts between BoringSSL (used in the
    # gRPC library in the backing layer) and OpenSSL (which the bridge layer
    # links against).
    #
    # Minimizing the number of visible symbols has additional benefits; see
    # https://gcc.gnu.org/wiki/Visibility for more information.
    global_copts = ["-fvisibility=hidden"],
    linkshared = 1,
    linkstatic = 1,
    deps = [
        ":export_macros",
        "//src/backing/client",
        "//src/backing/client:crypto_key_version_algorithm",
        "//src/backing/client:digest_case",
        "//src/backing/client:public_key",
        "//src/backing/client/grpc_client:client_context_factory",
        "//src/backing/client/grpc_client:key_management_service_stub",
        "//src/backing/client/grpc_client:proto_util",
        "//src/backing/crypto_key_handle",
        "//src/backing/status",
        "//src/backing/status:status_or",
    ],
)

cc_library(
    name = "export_macros",
    hdrs = ["export_macros.h"],
)

filegroup(
    name = "bridge_headers",
    srcs = [
        "export_macros.h",
        "//src/backing/client:bridge_headers",
        "//src/backing/crypto_key_handle:bridge_headers",
        "//src/backing/status:bridge_headers",
    ],
)
