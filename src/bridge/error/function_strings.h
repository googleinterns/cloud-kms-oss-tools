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

#ifndef KMSENGINE_BRIDGE_ERROR_FUNCTION_STRINGS_H_
#define KMSENGINE_BRIDGE_ERROR_FUNCTION_STRINGS_H_

#include <stdio.h>

#include <openssl/err.h>

#include "src/bridge/error/error_codes.h"

namespace kmsengine {
namespace bridge {
namespace error {

// Returns an OpenSSL-friendly error code for the given FunctionCode. Helper
// function meant for constructing an ERR_STRING_DATA object.
inline unsigned long GenerateOpenSSLFunctionErrorCode(FunctionCode func) {
  // The first argument to ERR_PACK will be packed in by OpenSSL, so leave it
  // as 0. The second argument is a "function code" defined by our engine. The
  // third argument is a "reason code" (left as 0 since the reason strings are
  // separately loaded from the function strings).
  return ERR_PACK(0, static_cast<std::underlying_type<FunctionCode>>(func), 0);
}

// Numerical constants representing an OpenSSL function.
enum class FunctionCode : int {
  kRsaPubEnc = 0,
  kRsaPubDec,
  kRsaPrivEnc,
  kRsaPrivDec,
  kRsaSign,
  kRsaVerify,
};

// Associates each EngineFunction code with a human-readable string.
const std::vector<ERR_STRING_DATA> kFunctionStrings = {
  {GenerateOpenSSLFunctionErrorCode(FunctionCode::kRsaPubEnc),
    "RsaPubEnc"},
  {GenerateOpenSSLFunctionErrorCode(FunctionCode::kRsaPubDec),
    "RsaPubDec"},
  {GenerateOpenSSLFunctionErrorCode(FunctionCode::kRsaPrivEnc),
    "RsaPrivEnc"},
  {GenerateOpenSSLFunctionErrorCode(FunctionCode::kRsaPrivDec),
    "RsaPrivDec"},
  {GenerateOpenSSLFunctionErrorCode(FunctionCode::kRsaSign),
    "RsaSign"},
  {GenerateOpenSSLFunctionErrorCode(FunctionCode::kRsaVerify),
    "RsaVerify"},
  {0, 0},  // OpenSSL requires ERR_STRING_DATA to end with {0, 0}.
};

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_FUNCTION_STRINGS_H_
