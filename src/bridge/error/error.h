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

#include "src/backing/status/status.h"

namespace kmsengine {
namespace bridge {

// Loads the engine error strings into OpenSSL. This associates human-
// readable error strings with the error codes signaled by the engine.
Status LoadErrorStringsIntoOpenSSL();

// Unloads the engine error strings from OpenSSL.
Status UnloadErrorStringsFromOpenSSL();

// Signals to OpenSSL that an error of reason `reason` occurred in
// function `function` at file `file` on line `line`.
//
// `KMSENGINE_SIGNAL_ERROR` should generally be used instead of
// `SignalErrorToOpenSSL` (the macro is defined separately to capture function
// names, file names, etc.).
void SignalErrorToOpenSSL(Status status, const char *function_name,
                          const char *file_name, int line_number);

// Signals to OpenSSL that an error of reason `reason_code` occurred. This does
// not throw an exception.
//
// `LoadErrorStrings` does NOT need to be called before this function is
// called. If it has not yet been called, then OpenSSL won't print human-
// readable strings.
//
// Example:
//
//    StatusOr<SomeType> status_or = ReturnsErrorStatus();
//    if (!status_or.ok()) {
//      KMSENGINE_SIGNAL_ERROR(status_or.status());
//      return 0;
//    }
//
// Defined as a macro that expands to `SignalErrorToOpenSSL` and adds the
// `__func__`, `__FILE__`, and `__LINE__` parameters.
#define KMSENGINE_SIGNAL_ERROR(status) \
  SignalErrorToOpenSSL(status, __func__, __FILE__, __LINE__);

// Returns the library code assigned by OpenSSL.
int GetLibraryCode();

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_ERROR_H_
