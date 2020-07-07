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

inline ERR_STRING_DATA MakeErrStringData(StatusCode code) {
  return ERR_STRING_DATA{
    PackReasonCode(code), StatusCodeToString(code).c_str()
  };
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
  MakeErrStringData(StatusCode::kOk),
  MakeErrStringData(StatusCode::kCancelled),
  MakeErrStringData(StatusCode::kUnknown),
  MakeErrStringData(StatusCode::kInvalidArgument),
  MakeErrStringData(StatusCode::kDeadlineExceeded),
  MakeErrStringData(StatusCode::kNotFound),
  MakeErrStringData(StatusCode::kAlreadyExists),
  MakeErrStringData(StatusCode::kPermissionDenied),
  MakeErrStringData(StatusCode::kResourceExhausted),
  MakeErrStringData(StatusCode::kFailedPrecondition),
  MakeErrStringData(StatusCode::kAborted),
  MakeErrStringData(StatusCode::kOutOfRange),
  MakeErrStringData(StatusCode::kUnimplemented),
  MakeErrStringData(StatusCode::kInternal),
  MakeErrStringData(StatusCode::kUnavailable),
  MakeErrStringData(StatusCode::kDataLoss),
  MakeErrStringData(StatusCode::kUnauthenticated),
  {0, 0},  // OpenSSL requires array to end with {0, 0}.
};

}  // namespace error_impl
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_ERROR_STRINGS_H_
