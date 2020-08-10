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
 * Original EqualsProto tests copyright 2020 Google LLC
 *
 *    - Renamed namespaces and file includes
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

#include <gmock/gmock.h>
#include <google/protobuf/wrappers.pb.h>
#include <gtest/gtest.h>

#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace testing_util {
namespace {

using ::testing::Not;

const Status kCancelled = Status(StatusCode::kCancelled, "cancelled");
const Status kNotFound = Status(StatusCode::kNotFound, "not found");

TEST(IsOk, WorksWithStatus) {
  EXPECT_THAT(Status(StatusCode::kOk, "test"), IsOk());
  EXPECT_THAT(kCancelled, Not(IsOk()));
  EXPECT_THAT(kNotFound, Not(IsOk()));
}

TEST(IsOk, WorksWithStatusOr) {
  EXPECT_THAT(StatusOr<int>(1), IsOk());
  EXPECT_THAT(StatusOr<int>(kCancelled), Not(IsOk()));
  EXPECT_THAT(StatusOr<int>(kNotFound), Not(IsOk()));
}

TEST(EqualsProto, Basic) {
  ::google::protobuf::StringValue actual;
  actual.set_value("Hello World");
  ::google::protobuf::StringValue not_actual;

  EXPECT_THAT(actual, EqualsProto(actual));
  EXPECT_THAT(actual, Not(EqualsProto(not_actual)));
}

}  // namespace
}  // namespace testing_util
}  // namespace kmsengine
