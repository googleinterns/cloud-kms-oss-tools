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

#include "src/bridge/error/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error {

// Generates a vector of `ERR_STRING_DATA` structs that map `StatusCodes` to
// human-readable error strings. These structs should be passed to OpenSSL as
// an array in a call to `ERR_load_strings` to associate the strings with each
// of the status codes.
std::vector<ERR_STRING_DATA> MakeReasonErrorStrings();

// Generates a vector of `ERR_STRING_DATA` structs that map `StatusCodes` to
// human-readable error strings. These structs should be passed to OpenSSL as
// an array in a call to `ERR_load_strings` to associate the strings with each
// of the status codes.
std::vector<ERR_STRING_DATA> MakeFunctionErrorStrings() {
  return kFunctionStrings;
}

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ERROR_ERROR_STRINGS_H_
