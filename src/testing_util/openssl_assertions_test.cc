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
#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "src/testing_util/openssl_assertions.h"
#include "src/bridge/error/error.h"

namespace kmsengine {
namespace testing_util {
namespace {

// Returns falsy value on error.
int ExpectedToError() {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kInternal,
                                "a unique error message"));
  return 0;
}

// Returns truthy value on success.
int ExpectedToSucceed() {
  return 1;
}

TEST(OpenSslSuccessTest, ExpectsSuccess) {
  EXPECT_OPENSSL_SUCCESS(ExpectedToSucceed());
  ASSERT_OPENSSL_SUCCESS(ExpectedToSucceed());
}

TEST(OpenSslSuccessTest, FailsOnFailure) {
  EXPECT_NONFATAL_FAILURE(
      EXPECT_OPENSSL_SUCCESS(ExpectedToError()),
      "unexpectedly returned false");
  EXPECT_FATAL_FAILURE(
      ASSERT_OPENSSL_SUCCESS(ExpectedToError()),
      "unexpectedly returned false");
}

TEST(OpenSslFailureTest, MatchesErrorMessage) {
  EXPECT_OPENSSL_FAILURE(ExpectedToError(), "a unique error message");
  ASSERT_OPENSSL_FAILURE(ExpectedToError(), "a unique error message");
}

TEST(OpenSslFailureTest, MatchesSubstringErrorMessage) {
  EXPECT_OPENSSL_FAILURE(ExpectedToError(), "error message");
  ASSERT_OPENSSL_FAILURE(ExpectedToError(), "error message");

  EXPECT_OPENSSL_FAILURE(ExpectedToError(), "");
  ASSERT_OPENSSL_FAILURE(ExpectedToError(), "");
}

TEST(OpenSslFailureTest, FailsOnSuccess) {
  EXPECT_NONFATAL_FAILURE(
      EXPECT_OPENSSL_FAILURE(ExpectedToSucceed(), ""),
      "unexpectedly returned true");
  EXPECT_FATAL_FAILURE(
      ASSERT_OPENSSL_FAILURE(ExpectedToSucceed(), ""),
      "unexpectedly returned true");
}

}  // namespace
}  // namespace testing_util
}  // namespace kmsengine
