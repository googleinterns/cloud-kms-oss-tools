/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>

#include <openssl/err.h>
#include <gtest/gtest.h>

#include "src/backing/status/status.h"
#include "src/bridge/error/error_strings.h"

namespace kmsengine {
namespace bridge {
namespace error_impl {
namespace {

const StatusCode kStatusCodes[] = {
  StatusCode::kOk,
  StatusCode::kCancelled,
  StatusCode::kUnknown,
  StatusCode::kInvalidArgument,
  StatusCode::kDeadlineExceeded,
  StatusCode::kNotFound,
  StatusCode::kAlreadyExists,
  StatusCode::kPermissionDenied,
  StatusCode::kUnauthenticated,
  StatusCode::kResourceExhausted,
  StatusCode::kFailedPrecondition,
  StatusCode::kAborted,
  StatusCode::kOutOfRange,
  StatusCode::kUnimplemented,
  StatusCode::kInternal,
  StatusCode::kUnavailable,
  StatusCode::kDataLoss,
};

TEST(ErrorStringsTest, PackReasonCode) {
  for (auto code : kStatusCodes) {
    auto packed_code = PackReasonCode(code);

    // Library and function components should not be set.
    EXPECT_EQ(ERR_GET_LIB(packed_code), 0);
    EXPECT_EQ(ERR_GET_FUNC(packed_code), 0);

    // Reason code value should be equivalent to underlying `StatusCode` value.
    EXPECT_EQ(ERR_GET_REASON(packed_code), StatusCodeToInt(code));
  }
}

TEST(ErrorStringsTest, AllStatusCodesInReasonStrings) {
  for (auto code : kStatusCodes) {
    auto count = sizeof(kReasonStrings) / sizeof(kReasonStrings[0]);
    auto end = kReasonStrings + count;
    auto result = std::find_if(kReasonStrings, end,
                 [=](ERR_STRING_DATA data)->bool {
      return (ERR_GET_REASON(data.error) == StatusCodeToInt(code));
    });

    // If result == end, then no reason string was found for the given code.
    EXPECT_NE(result, end);
  }
}

}  // namespace
}  // namespace error_impl
}  // namespace bridge
}  // namespace kmsengine
