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
 * Modifications copyright 2020 Google LLC
 *
 *    - Renamed namespaces and file includes
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

namespace kmsengine {
namespace {

TEST(Status, StatusCodeToString) {
  EXPECT_EQ("OK", StatusCodeToString(StatusCode::kOk));
  EXPECT_EQ("CANCELLED", StatusCodeToString(StatusCode::kCancelled));
  EXPECT_EQ("UNKNOWN", StatusCodeToString(StatusCode::kUnknown));
  EXPECT_EQ("INVALID_ARGUMENT",
            StatusCodeToString(StatusCode::kInvalidArgument));
  EXPECT_EQ("DEADLINE_EXCEEDED",
            StatusCodeToString(StatusCode::kDeadlineExceeded));
  EXPECT_EQ("NOT_FOUND", StatusCodeToString(StatusCode::kNotFound));
  EXPECT_EQ("ALREADY_EXISTS", StatusCodeToString(StatusCode::kAlreadyExists));
  EXPECT_EQ("PERMISSION_DENIED",
            StatusCodeToString(StatusCode::kPermissionDenied));
  EXPECT_EQ("UNAUTHENTICATED",
            StatusCodeToString(StatusCode::kUnauthenticated));
  EXPECT_EQ("RESOURCE_EXHAUSTED",
            StatusCodeToString(StatusCode::kResourceExhausted));
  EXPECT_EQ("FAILED_PRECONDITION",
            StatusCodeToString(StatusCode::kFailedPrecondition));
  EXPECT_EQ("ABORTED", StatusCodeToString(StatusCode::kAborted));
  EXPECT_EQ("OUT_OF_RANGE", StatusCodeToString(StatusCode::kOutOfRange));
  EXPECT_EQ("UNIMPLEMENTED", StatusCodeToString(StatusCode::kUnimplemented));
  EXPECT_EQ("INTERNAL", StatusCodeToString(StatusCode::kInternal));
  EXPECT_EQ("UNAVAILABLE", StatusCodeToString(StatusCode::kUnavailable));
  EXPECT_EQ("DATA_LOSS", StatusCodeToString(StatusCode::kDataLoss));
  EXPECT_EQ("UNEXPECTED_STATUS_CODE=42",
            StatusCodeToString(static_cast<StatusCode>(42)));
}

}  // namespace
}  // namespace kmsengine
