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

#ifndef KMSENGINE_BRIDGE_ERROR_IMPL_ERROR_STRINGS_H_
#define KMSENGINE_BRIDGE_ERROR_IMPL_ERROR_STRINGS_H_

#include <stdio.h>

#include <openssl/err.h>

#include "src/backing/status/status.h"
#include "src/bridge/engine_name.h"
#include "src/bridge/error_impl/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error_impl {

// Returns an Open-SSL friendly error code for the given StatusCode. Helper
// function meant for constructing an ERR_STRING_DATA object.
unsigned long PackReasonCode(StatusCode reason);

// Returns an OpenSSL-friendly error code for the given FunctionCode. Helper
// function meant for constructing an ERR_STRING_DATA object.
unsigned long PackFunctionCode(FunctionCode func);

// Associates the library code with the engine name.
//
// Purposely not declared as `const`. OpenSSL will modify the ERR_STRING_DATA
// tables when strings are loaded (it updates the leading bits of the first
// error number argument to patch in the assigned error library code).
ERR_STRING_DATA kLibraryStrings[] = {
  {ERR_PACK(0, 0, 0), kEngineName},  // (0, 0, 0) denotes engine name.
  {0, 0},
};

// Map from StatusCodes to human-readable strings.
//
// Purposely not declared as `const`. See `kLibraryStrings` comment for info.
ERR_STRING_DATA kReasonStrings[] = {
  {PackReasonCode(StatusCode::kOk), "ok"},
  {PackReasonCode(StatusCode::kCancelled), "cancelled"},
  {PackReasonCode(StatusCode::kUnknown), "unknown"},
  {PackReasonCode(StatusCode::kInvalidArgument), "invalid argument"},
  {PackReasonCode(StatusCode::kDeadlineExceeded), "deadline exceeded"},
  {PackReasonCode(StatusCode::kNotFound), "not found"},
  {PackReasonCode(StatusCode::kAlreadyExists), "already exists"},
  {PackReasonCode(StatusCode::kPermissionDenied), "permission denied"},
  {PackReasonCode(StatusCode::kResourceExhausted), "resource exhausted"},
  {PackReasonCode(StatusCode::kFailedPrecondition), "failed precondition"},
  {PackReasonCode(StatusCode::kAborted), "aborted"},
  {PackReasonCode(StatusCode::kOutOfRange), "out of range"},
  {PackReasonCode(StatusCode::kUnimplemented), "unimplemented"},
  {PackReasonCode(StatusCode::kInternal), "internal"},
  {PackReasonCode(StatusCode::kUnavailable), "unavailable"},
  {PackReasonCode(StatusCode::kDataLoss), "data loss"},
  {PackReasonCode(StatusCode::kUnauthenticated), "unauthenticated"},
  {0, 0},
};

// Map from FunctionCodes to human-readable strings.
//
// Purposely not declared as `const`. See `kLibraryStrings` comment for info.
ERR_STRING_DATA kFunctionStrings[] = {
  {PackFunctionCode(FunctionCode::kRsaPubEnc), "RsaPubEnc"},
  {PackFunctionCode(FunctionCode::kRsaPubDec), "RsaPubDec"},
  {PackFunctionCode(FunctionCode::kRsaPrivEnc), "RsaPrivEnc"},
  {PackFunctionCode(FunctionCode::kRsaPrivDec), "RsaPrivDec"},
  {PackFunctionCode(FunctionCode::kRsaSign), "RsaSign"},
  {PackFunctionCode(FunctionCode::kRsaVerify), "RsaVerify"},
  {0, 0},
};

}  // namespace error_impl
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_IMPL_ERROR_STRINGS_H_
