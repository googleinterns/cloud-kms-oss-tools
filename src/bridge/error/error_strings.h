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

#include <openssl/err.h>

#include "src/backing/status/status.h"
#include "src/bridge/engine_name.h"

namespace kmsengine {
namespace bridge {
namespace error_impl {

// Returns an OpenSSL friendly error code for the given `StatusCode`. Helper
// function meant for constructing an ERR_STRING_DATA object.
inline unsigned long PackReasonCode(StatusCode code) {
  // The first argument is the "error library code" assigned to our engine by
  // OpenSSL, so leave as zero. The second argument is a "function code" (left
  // as 0 since the reason strings are separately loaded from the function
  // strings). The third argument is a "reason code" defined by our engine.
  return ERR_PACK(0, 0, StatusCodeToInt(code));
}

// Associates the library code with the engine name.
//
// Purposely not declared as `const`. OpenSSL will modify the ERR_STRING_DATA
// tables when strings are loaded (it updates the leading bits of the first
// error number argument to patch in the assigned error library code).
ERR_STRING_DATA kLibraryStrings[] = {
  {ERR_PACK(0, 0, 0), kEngineName},  // (0, 0, 0) denotes engine name.
  {0, 0},  // OpenSSL requires array to end with {0, 0}.
};

// Map from StatusCodes to human-readable strings.
//
// Purposely not declared as `const`. See `kLibraryStrings` comment for info.
ERR_STRING_DATA kReasonStrings[] = {
  {PackReasonCode(StatusCode::kOk), "OK"},
  {PackReasonCode(StatusCode::kCancelled), "CANCELLED"},
  {PackReasonCode(StatusCode::kUnknown), "UNKNOWN"},
  {PackReasonCode(StatusCode::kInvalidArgument), "INVALID_ARGUMENT"},
  {PackReasonCode(StatusCode::kDeadlineExceeded), "DEADLINE_EXCEEDED"},
  {PackReasonCode(StatusCode::kNotFound), "NOT_FOUND"},
  {PackReasonCode(StatusCode::kAlreadyExists), "ALREADY_EXISTS"},
  {PackReasonCode(StatusCode::kPermissionDenied), "PERMISSION_DENIED"},
  {PackReasonCode(StatusCode::kResourceExhausted), "RESOURCE_EXHAUSTED"},
  {PackReasonCode(StatusCode::kFailedPrecondition), "FAILED_PRECONDITION"},
  {PackReasonCode(StatusCode::kAborted), "ABORTED"},
  {PackReasonCode(StatusCode::kOutOfRange), "OUT_OF_RANGE"},
  {PackReasonCode(StatusCode::kUnimplemented), "UNIMPLEMENTED"},
  {PackReasonCode(StatusCode::kInternal), "INTERNAL"},
  {PackReasonCode(StatusCode::kUnavailable), "UNAVAILABLE"},
  {PackReasonCode(StatusCode::kDataLoss), "DATA_LOSS"},
  {PackReasonCode(StatusCode::kUnauthenticated), "UNAUTHENTICATED"},
  {0, 0},  // OpenSSL requires array to end with {0, 0}.
};

}  // namespace error_impl
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_ERROR_STRINGS_H_
