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

#ifndef KMSENGINE_BRIDGE_ERROR_ERROR_STRINGS_H_
#define KMSENGINE_BRIDGE_ERROR_ERROR_STRINGS_H_

#include <stdio.h>

#include <openssl/err.h>

#include "absl/status/status.h"
#include "src/backing/status/status_code.h"
#include "src/bridge/error/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error {

// Returns an Open-SSL friendly error code for the given StatusCode. Helper
// function meant for constructing an ERR_STRING_DATA object.
inline unsigned long PackReasonCode(StatusCode reason);

// Returns an OpenSSL-friendly error code for the given FunctionCode. Helper
// function meant for constructing an ERR_STRING_DATA object.
inline unsigned long PackFunctionCode(FunctionCode func);

// Map from StatusCodes to human-readable strings.
const ERR_STRING_DATA kReasonStrings[] = {
  {PackReasonCode(StatusCode::kOk),
      absl::StatusCodeToString(StatusCode::kOk)}
  {PackReasonCode(StatusCode::kCancelled),
      absl::StatusCodeToString(StatusCode::kCancelled)}
  {PackReasonCode(StatusCode::kUnknown),
      absl::StatusCodeToString(StatusCode::kUnknown)}
  {PackReasonCode(StatusCode::kInvalidArgument),
      absl::StatusCodeToString(StatusCode::kInvalidArgument)}
  {PackReasonCode(StatusCode::kDeadlineExceeded),
      absl::StatusCodeToString(StatusCode::kDeadlineExceeded)}
  {PackReasonCode(StatusCode::kNotFound),
      absl::StatusCodeToString(StatusCode::kNotFound)}
  {PackReasonCode(StatusCode::kAlreadyExists),
      absl::StatusCodeToString(StatusCode::kAlreadyExists)}
  {PackReasonCode(StatusCode::kPermissionDenied),
      absl::StatusCodeToString(StatusCode::kPermissionDenied)}
  {PackReasonCode(StatusCode::kResourceExhausted),
      absl::StatusCodeToString(StatusCode::kResourceExhausted)}
  {PackReasonCode(StatusCode::kFailedPrecondition),
      absl::StatusCodeToString(StatusCode::kFailedPrecondition)}
  {PackReasonCode(StatusCode::kAborted),
      absl::StatusCodeToString(StatusCode::kAborted)}
  {PackReasonCode(StatusCode::kOutOfRange),
      absl::StatusCodeToString(StatusCode::kOutOfRange)}
  {PackReasonCode(StatusCode::kUnimplemented),
      absl::StatusCodeToString(StatusCode::kUnimplemented)}
  {PackReasonCode(StatusCode::kInternal),
      absl::StatusCodeToString(StatusCode::kInternal)}
  {PackReasonCode(StatusCode::kUnavailable),
      absl::StatusCodeToString(StatusCode::kUnavailable)}
  {PackReasonCode(StatusCode::kDataLoss),
      absl::StatusCodeToString(StatusCode::kDataLoss)}
  {PackReasonCode(StatusCode::kUnauthenticated),
      absl::StatusCodeToString(StatusCode::kUnauthenticated)}
  {0, 0},
};

// Map from FunctionCodes to human-readable strings.
const ERR_STRING_DATA kFunctionStrings[] = {
  {PackFunctionCode(FunctionCode::kRsaPubEnc), "RsaPubEnc"},
  {PackFunctionCode(FunctionCode::kRsaPubDec), "RsaPubDec"},
  {PackFunctionCode(FunctionCode::kRsaPrivEnc), "RsaPrivEnc"},
  {PackFunctionCode(FunctionCode::kRsaPrivDec), "RsaPrivDec"},
  {PackFunctionCode(FunctionCode::kRsaSign), "RsaSign"},
  {PackFunctionCode(FunctionCode::kRsaVerify), "RsaVerify"},
  {0, 0},
};

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_ERROR_STRINGS_H_
