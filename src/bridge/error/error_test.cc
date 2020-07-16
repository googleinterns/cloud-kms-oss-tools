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

#include <tuple>

#include <openssl/engine.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/strings/str_cat.h"
#include "src/backing/status/status.h"
#include "src/bridge/engine_name.h"
#include "src/bridge/error/error.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::testing::ValuesIn;
using ::testing::Combine;
using ::testing::StrEq;
using ::testing::HasSubstr;

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

const std::string kSampleStrings[] = {
  "a very long, unique error message",
  "short message",
  "",
};

class ErrorSignalTest : public
    testing::TestWithParam<std::tuple<StatusCode, std::string>> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(InstantiationName, ErrorSignalTest,
                         Combine(ValuesIn(kStatusCodes),
                                 ValuesIn(kSampleStrings)));

TEST_P(ErrorSignalTest, SignalErrorWorks) {
  // Empty the OpenSSL error queue, just in case.
  ERR_clear_error();

  auto expected_code = std::get<0>(GetParam());
  auto expected_message = std::get<1>(GetParam());
  KMSENGINE_SIGNAL_ERROR(Status(expected_code, expected_message));

  // OpenSSL should have the error we just signaled in its own error queue, so
  // pop it off the queue and interpret its strings.
  const char *file, *data;
  int line, flags;
  auto err = ERR_get_error_line_data(&file, &line, &data, &flags);

  EXPECT_THAT(file, StrEq(__FILE__));
  EXPECT_THAT(data, HasSubstr(__func__));
  EXPECT_THAT(data, HasSubstr(expected_message));

  EXPECT_EQ(ERR_GET_LIB(err), GetErrorLibraryId());
  EXPECT_EQ(ERR_GET_FUNC(err), 0);
  EXPECT_EQ(ERR_GET_REASON(err), StatusCodeToInt(expected_code));
}

TEST(ErrorTest, ErrorLibraryCodeInitialized) {
  // Library codes should be greater than zero.
  EXPECT_GT(GetErrorLibraryId(), 0);
}

TEST(ErrorTest, ErrorLibraryCodeConstantBetweenCalls) {
  // Library codes should be greater than zero.
  auto first_code = GetErrorLibraryId();
  auto second_code = GetErrorLibraryId();
  EXPECT_EQ(first_code, second_code);
}

TEST(ErrorTest, LoadErrorStrings) {
  // Actual error string loading doesn't work outside of the engine context,
  // so for now just check that the loader functions are callable and returns a
  // success `Status`.
  EXPECT_THAT(LoadErrorStringsIntoOpenSSL(), IsOk());
  EXPECT_THAT(UnloadErrorStringsFromOpenSSL(), IsOk());
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
