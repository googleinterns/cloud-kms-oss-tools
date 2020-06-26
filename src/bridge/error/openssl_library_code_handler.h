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

#ifndef KMSENGINE_BRIDGE_ERROR_OPENSSL_LIBRARY_CODE_HANDLER_H_
#define KMSENGINE_BRIDGE_ERROR_OPENSSL_LIBRARY_CODE_HANDLER_H_

#include "src/bridge/error/error_handler.h"

#include <stdio.h>

#include <openssl/err.h>

namespace kmsengine {
namespace bridge {
namespace error {

// Manages the "library code" assigned to our engine by OpenSSL.
//
// OpenSSL engines request a library code using ERR_get_next_error_library(3)
// with which they can register engine-specific, human-readable error strings
// with OpenSSL. This utility class provides a wrapper around the library
// code.
class OpenSSLLibraryCodeHandler {
 public:
  // OpenSSLLibraryCodeHandler is trivially constructible and destructible.
  OpenSSLLibraryCodeHandler() {}
  ~OpenSSLLibraryCodeHandler() {}

  // OpenSSLLibraryCodeHandler is not copyable or movable.
  OpenSSLLibraryCodeHandler(const OpenSSLLibraryCodeHandler&) = delete;
  OpenSSLLibraryCodeHandler& operator=(const OpenSSLLibraryCodeHandler&)
      = delete;

  // Returns the non-zero library code that was assigned to the engine by
  // OpenSSL.
  //
  // If an error library code has not already been assigned, requests one from
  // OpenSSL and caches and returns the new code.
  int GetLibraryCode() {
    if (openssl_library_code_ == 0) {
      openssl_library_code_ = ERR_get_next_error_library();
    }
    return openssl_library_code_;
  }

 private:
  // Holds the library code assigned to our engine by OpenSSL from a call to
  // ERR_get_next_error_library. If 0, no library code has been assigned.
  int openssl_library_code_ = 0;
};

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_OPENSSL_LIBRARY_CODE_HANDLER_H_
