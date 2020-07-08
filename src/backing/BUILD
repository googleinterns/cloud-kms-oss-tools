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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library", "cc_test")

package(default_visibility = ["//src:__subpackages__"])

cc_import(
    name = "backing",
    hdrs = [":headers"],
    shared_library = ":libkms.so",
)

cc_binary(
    name = "libkms.so",
    srcs = ["//src/backing/status:sources"],
    linkstatic = 1,
    linkshared = 1,
    deps = [
        "//src/backing/status",
        "//src/backing/status:status_or",
    ],
)

filegroup(
    name = "headers",
    srcs = [
        "//src/backing/status:bridge_headers",
    ],
)
