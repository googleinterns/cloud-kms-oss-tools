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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(default_visibility = ["//test:__subpackages__"])

cc_binary(
    name = "libengine.so",
    srcs = ["main.c"],
    deps = [":engine_bind"],
    linkopts = ["-lcrypto"],
    linkshared = 1,  # Build as a shared object.
    linkstatic = 0,
    visibility = ["//visibility:public"],
)

cc_library(
    name = "engine_bind",
    srcs = ["engine_bind.cc"],
    hdrs = ["engine_bind.h"],
    deps = [
        ":engine_setup",
        ":engine_name",
    ],
    linkopts = ["-lcrypto"],
)

cc_library(
    name = "engine_name",
    hdrs = ["engine_name.h"],
)

cc_library(
    name = "engine_setup",
    srcs = ["engine_setup.cc"],
    hdrs = ["engine_setup.h"],
    linkopts = ["-lcrypto"],
)
