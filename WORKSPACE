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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

"""
OpenSSL dependencies.

OpenSSL does not have its own Bazel BUILD configuration. We import `rules_foreign_cc`
to get around this, which defines the `configure_make` rule which our BUILD file can
use to run OpenSSL's CMake file.

See https://stackoverflow.com/a/58106111 for reference.
"""

# Group the sources of the library so that rules in rules_foreign_cc have access to it.
# all_content = """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])"""

# http_archive(
#     name = "openssl",
#     build_file_content = all_content,
#     sha256 = "f6fb3079ad15076154eda9413fed42877d668e7069d9b87396d0804fdb3f4c90",
#     strip_prefix = "openssl-1.1.1c",
#     urls = ["https://www.openssl.org/source/openssl-1.1.1c.tar.gz"],
# )

# This overrides @boringssl in grpc_deps. Then, it defines the :ssl target so
# that when gRPC is built and refers to @boringssl//:ssl, it uses the local
# OpenSSL installation instead.
new_local_repository(
    name = "boringssl",
    path = "/usr/include/openssl",
    build_file_content = """
package(default_visibility = ["//visibility:public"])
cc_library(
    name = "ssl",
    hdrs = glob(["**/*.h"])
)
"""
)


# `rules_foreign_cc` library needed for `configure_make`.
http_archive(
    name = "rules_foreign_cc",
    sha256 = "3b21a34d803f2355632434865c39d122a57bf3bf8bb2636e27b474aeac455e5c",
    strip_prefix = "rules_foreign_cc-master",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/master.zip",
)

load("@rules_foreign_cc//:workspace_definitions.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()

"""
Google Cloud C++ API dependencies.

Currently, there is no official C++ client for Google Cloud KMS. However, the repository
includes useful Bazel rules and targets for working with the canonical protobuf definitions
for Cloud KMS (see https://github.com/googleapis/googleapis/tree/master/google/cloud/kms/v1).
"""

# Import Google APIs with C++ rules.
git_repository(
    name = "com_github_googleapis_google_cloud_cpp",
    branch = "v1.14.x",
    remote = "https://github.com/googleapis/google-cloud-cpp",
)

# Load Google Cloud C++ API dependencies. This also imports other dependencies (such as
# @com_google_googleapis, @com_github_googletest, and @com_github_grpc_grpc).
load("@com_github_googleapis_google_cloud_cpp//bazel:google_cloud_cpp_deps.bzl", "google_cloud_cpp_deps")

google_cloud_cpp_deps()

# Configure @com_google_googleapis to only compile C++ and gRPC libraries.
load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,  # Note: C++ support is only "Partially implemented".
    grpc = True,
)

# Configure gRPC dependencies.
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")

grpc_extra_deps()

