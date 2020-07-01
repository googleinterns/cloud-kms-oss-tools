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

#include <openssl/engine.h>
#include <gtest/gtest.h>

#include "src/bridge/error_impl/error.h"

namespace kmsengine {
namespace bridge {
namespace {

// Testing helper for making an OpenSSL error code associated with the KMS
// engine library from a function code.
constexpr auto TestFunctionCode(FunctionCode code) {
  return ERR_PACK(kErrorLibraryCode, FunctionCodeToInt(FunctionCode::kRsaSign),
                  0);
}

// Testing helper for making an OpenSSL error code associated with the KMS
// engine library from a status code.
constexpr auto TestReasonCode(StatusCode code) {
  return ERR_PACK(kErrorLibraryCode, StatusCodeToInt(StatusCode::kRsaSign),
                  0);
}

TEST(ErrorTest, FunctionStringsLoaded) {
  LoadErrorStringsIntoOpenSSL();

  EXPECT_EQ(ERR_func_error_string(TestFunctionCode(kRsaSign)), "RsaSign");
  EXPECT_EQ(ERR_func_error_string(TestFunctionCode(kRsaVerify)), "RsaVerify");

  UnloadErrorStringsFromOpenSSL();
}

TEST(ErrorTest, ReasonStringsLoaded) {
  LoadErrorStringsIntoOpenSSL();

  EXPECT_EQ(ERR_func_error_string(TestReasonCode(kCancelled)), "cancelled");
  EXPECT_EQ(ERR_func_error_string(TestReasonCode(kUnknown)), "unknown");
  EXPECT_EQ(ERR_func_error_string(TestReasonCode(kInternal)), "internal");
  EXPECT_EQ(ERR_func_error_string(TestReasonCode(kDataLoss)), "data loss");

  UnloadErrorStringsFromOpenSSL();
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
