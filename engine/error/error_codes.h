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

#ifndef ENGINE_ERROR_ERROR_CODES_H_
#define ENGINE_ERROR_ERROR_CODES_H_

#include <stdio.h>

#include "openssl/err.h"

namespace engine {

namespace error {

// Defines "function codes" for different functions called in our engine. Codes
// are intended to be associated with human-readable error strings such that if
// our engine signals to OpenSSL that an error occured in a function with code
// <code>, then OpenSSL will print out the human-readable string associated
// with <code>.
//
// See error_string.h for the human-readable error strings.
enum class EngineFunction {
  kExampleFunction = 0,
};


// Defines "reason codes" for possible error cases in our engine. Codes are
// intended to be associated with human-readable error strings such that if our
// engine signals to OpenSSL that an error occured due to reason with code
// <code>, then OpenSSL will print out the human-readable string associated
// with <code>.
//
// See error_string.h for the human-readable error strings.
enum class EngineErrorReason {
  kExampleReason = 0,
};

}  // namespace error

}  // namespace engine

#endif  // ENGINE_ERROR_ERROR_CODES_H_
