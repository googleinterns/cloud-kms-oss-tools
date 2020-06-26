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

#include "src/bridge/error/error.h"

#include <stdio.h>

#include <openssl/err.h>

#include "src/backing/status/status_code.h"
#include "src/bridge/error/error_strings.h"
#include "src/bridge/error/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error {

// OpenSSL engines request a library code using ERR_get_next_error_library(3)
// with which they can register engine-specific, human-readable error strings
// with OpenSSL.
static const int library_code = ERR_get_next_error_library();

void LoadErrorStringsIntoOpenSSL() {
  ERR_load_strings(library_code,
                   const_cast<ERR_STRING_DATA*>(kFunctionStrings));
  ERR_load_strings(library_code,
                   const_cast<ERR_STRING_DATA*>(kReasonStrings));
}

void UnloadErrorStringsFromOpenSSL() {
  ERR_unload_strings(library_code,
                     const_cast<ERR_STRING_DATA*>(kFunctionStrings));
  ERR_unload_strings(library_code,
                     const_cast<ERR_STRING_DATA*>(kReasonStrings));
}

void ErrEngineError(FunctionCode function, StatusCode reason, char *file,
                    int line) {
  ERR_PUT_error(library_code,
                static_cast<std::underlying_type<FunctionCode>::type>(function),
                static_cast<std::underlying_type<StatusCode>::type>(reason),
                file, line);
}

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine
