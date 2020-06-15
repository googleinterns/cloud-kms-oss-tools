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

#ifndef ENGINE_ERROR_ERROR_HANDLER_H_
#define ENGINE_ERROR_ERROR_HANDLER_H_

#include <stdio.h>

#include "openssl/err.h"

namespace engine {

namespace error {

// Example
// https://github.com/engine-corner/engine-chil/blob/master/e_chil_err.c
class ErrorHandler {
 public:
  // Returns the singleton instance of ErrorHandler.
  static ErrorHandler& getInstance() {
    static ErrorHandler instance;
    // volatile int dummy{};
    return instance;
  }

  // ErrorHandler is not copyable.
  ErrorHandler(const ErrorHandler&) = delete;
  void operator=(const ErrorHandler&) = delete;

  // Loads the engine error strings into OpenSSL. This associates human-
  // readable error strings with the error codes signaled by the engine.
  //
  // It's safe to call this function even if UnloadErrorStrings has been
  // called.
  void LoadErrorStrings();

  // Unloads the engine error strings from OpenSSL.
  //
  // It's safe to call this function even if LoadErrorStrings has not been
  // called.
  void UnloadErrorStrings();

  // Signals to OpenSSL that an error of reason `reason` occurred in
  // function `function`. This function does not throw an exception, so the
  // caller should still continue executing.
  //
  // LoadErrorStrings does NOT need to be called before this function is
  // called. If it has not yet been called, then OpenSSL won't print human-
  // readable strings.
  //
  // Example:
  //   if (nonNull == NULL) {
  //     EngineErr(kFunction, kReason);
  //     return 0;
  //   }
  void EngineErr(int function, int reason);

 private:
  // Holds the library code assigned to our engine by OpenSSL from a call to
  // ERR_get_next_error_library. If 0, no library code has been assigned.
  //
  // This should not be accessed directly. Instead, use GetErrorLibraryCode.
  int ossl_library_error_code_ = 0;

  // Denotes whether or not error strings have been loaded in OpenSSL.
  bool strings_are_loaded_ = false;

  // ErrorHandler should only be instantiated via getInstance.
  ErrorHandler() {}

  // Signals to OpenSSL that an error of reason `reason` occurred in
  // function `function` at file `file` on line `line`.
  //
  // https://www.openssl.org/docs/man1.1.1/man3/ERR_put_error.html
  void ErrEngineError(int function, int reason, char *file, int line);

  // Returns the library code assigned to our engine by OpenSSL.
  int GetErrorLibraryCode();
};

}  // namespace error

}  // namespace engine

#endif  // ENGINE_ERROR_ERROR_HANDLER_H_
