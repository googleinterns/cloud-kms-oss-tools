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
 */

#include <gmock/gmock.h>

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

}  // namespace
}  // namespace testing_util
}  // namespace kmsengine
