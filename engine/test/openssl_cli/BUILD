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

# Note:
# sh_test rules cannot refer to non-sh_library or non-sh_binary dependencies in
# the `deps` field. Thus, we include libengine.so as a `data` dependency. Then,
# using Bazel's `rootpath` make variable, we retrieve the data path of
# libengine.so and pass the path to the shell script as an argument via `args`.
#
# Reference: https://jayconrod.com/posts/106/writing-bazel-rules--simple-binary-rule

sh_test(
  name = "load_engine_test",
  size = "small",
  srcs = ["load_engine_test.sh"],
  args = ["$(rootpath //engine:libengine.so)"],
  data = ["//engine:libengine.so"],
)
