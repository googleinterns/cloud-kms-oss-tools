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

#ifndef KMSENGINE_BRIDGE_ERROR_ERROR_H_
#define KMSENGINE_BRIDGE_ERROR_ERROR_H_

#include <stdio.h>

#include "src/backing/status/status_code.h"
#include "src/bridge/error/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error {

// Loads the engine error strings into OpenSSL. This associates human-
// readable error strings with the error codes signaled by the engine.
//
// It's safe to call this function even if UnloadErrorStringsFromOpenSSL has
// been called.
void LoadErrorStringsIntoOpenSSL();

// Unloads the engine error strings from OpenSSL.
//
// It's safe to call this function even if LoadErrorStringsIntoOpenSSL has not
// been called.
void UnloadErrorStringsFromOpenSSL();

// Signals to OpenSSL that an error of reason `reason_code` occurred in
// function `function_code`. This does not throw an exception.
//
// LoadErrorStrings does NOT need to be called before this function is
// called. If it has not yet been called, then OpenSSL won't print human-
// readable strings.
//
// Example:
//
//    if (nonNull == NULL) {
//      KMSENGINE_ERROR(kFunction, kReason);
//      return 0;
//    }
//
#define KMSENGINE_ERROR(function_code, reason_code) \
  ErrEngineError(function_code, reason_code, __FILE__, __LINE__)

// Signals to OpenSSL that an error occurred in function `function_code` due
// to the error status in the StatusOr<T> `status_or` object.
#define KMSENGINE_ERROR_WITH_STATUS_OR(function_code, status_or) \
  KMSENGINE_ERROR(function_code, status_or.status().code())

// Signals to OpenSSL that an error of reason `reason` occurred in
// function `function` at file `file` on line `line`.
//
// KMSENGINE_ERROR should generally be used instead of ErrEngineError.
void ErrEngineError(FunctionCode function, StatusCode reason, char *file, int line);

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_ERROR_H_
