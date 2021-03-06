/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Original EqualsProto version copyright 2020 Google LLC
 *
 *    - Renamed namespaces and file includes
 *    - Replaced Cloud C++ optional implementation with absl::optional
 *    - Renamed IsProtoEqual to EqualsProto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSENGINE_TESTING_UTIL_TEST_MATCHERS_H_
#define KMSENGINE_TESTING_UTIL_TEST_MATCHERS_H_

#include <string>

#include <google/protobuf/message.h>
#include <gmock/gmock.h>

#include "absl/strings/str_format.h"
#include "absl/types/optional.h"

namespace kmsengine {
namespace testing_util {

absl::optional<std::string> CompareProtos(
    google::protobuf::Message const& arg,
    google::protobuf::Message const& value);

MATCHER_P(EqualsProto, value,
          absl::StrFormat("proto %s", negation ? "does not equal" : "equals")) {
  absl::optional<std::string> delta = CompareProtos(arg, value);
  if (delta.has_value()) {
    *result_listener << "\n" << *delta;
  }
  return !delta.has_value();
}

MATCHER(IsOk, absl::StrFormat("status %s ok", negation ? "is not" : "")) {
  return arg.ok();
}

}  // namespace testing_util
}  // namespace kmsengine

#endif  // KMSENGINE_TESTING_UTIL_TEST_MATCHERS_H_
