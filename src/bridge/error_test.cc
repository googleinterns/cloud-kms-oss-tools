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

#include "src/backing/status/status.h"
#include "src/bridge/engine_name.h"
#include "src/bridge/error.h"
#include "src/bridge/error_impl/function_code.h"

namespace kmsengine {
namespace bridge {
namespace {

// Testing helper for making an OpenSSL error code associated with the KMS
// engine library from a function code.
unsigned long TestFunctionCode(FunctionCode code) {
  return ERR_PACK(GetLibraryCode(), FunctionCodeToInt(code), 0);
}

// Testing helper for making an OpenSSL error code associated with the KMS
// engine library from a status code.
unsigned long TestReasonCode(StatusCode code) {
  return ERR_PACK(GetLibraryCode(), StatusCodeToInt(code), 0);
}

TEST(ErrorTest, LibraryStringsLoaded) {
  LoadErrorStringsIntoOpenSSL();

  EXPECT_STREQ(ERR_lib_error_string(ERR_PACK(GetLibraryCode(), 0, 0)),
                                     kEngineName);

  UnloadErrorStringsFromOpenSSL();
}

TEST(ErrorTest, ReasonStringsLoaded) {
  LoadErrorStringsIntoOpenSSL();

  EXPECT_STREQ(ERR_reason_error_string(TestReasonCode(StatusCode::kCancelled)), "cancelled");
  EXPECT_STREQ(ERR_reason_error_string(TestReasonCode(StatusCode::kUnknown)), "unknown");
  EXPECT_STREQ(ERR_reason_error_string(TestReasonCode(StatusCode::kInternal)), "internal");
  EXPECT_STREQ(ERR_reason_error_string(TestReasonCode(StatusCode::kDataLoss)), "data loss");

  UnloadErrorStringsFromOpenSSL();
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
