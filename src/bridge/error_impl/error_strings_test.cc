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

#include "src/bridge/error_impl/error_strings.h"

namespace kmsengine {
namespace bridge {
namespace error_impl {
namespace {

TEST(ErrorStringsTest, PackReasonCodePacksIntoThirdArgument) {
  EXPECT_EQ(
      PackReasonCode(StatusCode::kOk),
      ERR_PACK(0, 0, StatusCodeToInt(StatusCode::kOk)));
  EXPECT_EQ(
      PackReasonCode(StatusCode::kUnknown),
      ERR_PACK(0, 0, StatusCodeToInt(StatusCode::kUnknown)));
  EXPECT_EQ(
      PackReasonCode(StatusCode::kCancelled),
      ERR_PACK(0, 0, StatusCodeToInt(StatusCode::kCancelled)));
}

TEST(ErrorStringsTest, PackFunctionCodePacksIntoSecondArgument) {
  EXPECT_EQ(
      PackFunctionCode(FunctionCode::kRsaSign),
      ERR_PACK(0, FunctionCodeToInt(FunctionCode::kRsaSign), 0));
  EXPECT_EQ(
      PackFunctionCode(FunctionCode::kRsaVerify),
      ERR_PACK(0, FunctionCodeToInt(FunctionCode::kRsaVerify), 0));
}

}  // namespace
}  // namespace error_impl
}  // namespace bridge
}  // namespace kmsengine
