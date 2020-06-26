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

#ifndef KMSENGINE_BRIDGE_ERROR_ERROR_PACK_H_
#define KMSENGINE_BRIDGE_ERROR_ERROR_PACK_H_

#include "src/bridge/error/error_strings.h"

#include <stdio.h>

#include <openssl/err.h>

#include "src/backing/status/status_code.h"

namespace kmsengine {
namespace bridge {
namespace error {
namespace {

// Returns an Open-SSL friendly error code for the given StatusCode. Helper
// function meant for constructing an ERR_STRING_DATA object.
inline unsigned long GenerateOpenSSLReasonErrorCode(StatusCode reason) {
  // The first argument to ERR_PACK will be packed in by OpenSSL, so leave it
  // as 0. The second argument is a "function code" (left as 0 since the reason
  // strings are separately loaded from the function strings). The second
  // argument is a "reason code" defined by our engine.
  return ERR_PACK(0, 0, static_cast<std::underlying_type<StatusCode>>(reason));
}

}  // namespace

static constexpr std::initializer_list<StatusCode> kStatusCodes = {
  StatusCode::kOk,
  StatusCode::kCancelled,
  StatusCode::kUnknown,
  StatusCode::kInvalidArgument,
  StatusCode::kDeadlineExceeded,
  StatusCode::kNotFound,
  StatusCode::kAlreadyExists,
  StatusCode::kPermissionDenied,
  StatusCode::kResourceExhausted,
  StatusCode::kFailedPrecondition,
  StatusCode::kAborted,
  StatusCode::kOutOfRange,
  StatusCode::kUnimplemented,
  StatusCode::kInternal,
  StatusCode::kUnavailable,
  StatusCode::kDataLoss,
  StatusCode::kUnauthenticated,
}

std::vector<ERR_STRING_DATA> MakeReasonStrings() {
  std::vector<ERR_STRING_DATA> result;
  result.reserve(kStatusCodes.size() + 1);  // Add 1 for the {0, 0} element.

  for (StatusCode code : kStatusCodes) {
    auto openssl_code = GenerateOpenSSLReasonErrorCode(code);
    auto error_string = absl::StatusCodeToString(code)
    result.push_back({openssl_code, error_string});
  }

  // OpenSSL requires ERR_STRING_DATA lists to end with {0, 0}.
  result.push_back({0, 0});
  return result;
}

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_ERROR_PACK_H_
