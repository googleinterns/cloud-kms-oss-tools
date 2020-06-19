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

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

"""
Google Cloud C++ API dependencies.
"""

# Import Google APIs with C++ rules.
git_repository(
    name = "com_github_googleapis_google_cloud_cpp",
    branch = "v1.14.x",
    remote = "https://github.com/googleapis/google-cloud-cpp",
)

# Load Google Cloud C++ API dependencies. This also imports other dependencies
# (such as @com_google_googleapis, @com_github_googletest, and
# @com_github_grpc_grpc).
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
