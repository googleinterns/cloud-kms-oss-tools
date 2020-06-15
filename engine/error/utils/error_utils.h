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

#ifndef ENGINE_ERROR_UTILS_ERROR_UTILS_H_
#define ENGINE_ERROR_UTILS_ERROR_UTILS_H_

#include <stdio.h>

#include "openssl/err.h"
#include "engine/error/error_codes.h"

namespace engine {

namespace error {

namespace utils {

// Returns an OpenSSL-friendly error code for the given function code. Helper
// function meant for constructing an ERR_STRING_DATA object.
unsigned long OsslErrorCodeForFunction(EngineFunction func) {
  // The first argument to ERR_PACK will be packed in by OpenSSL, so leave it
  // as 0. The second argument is a "function code" defined by our engine. The
  // third argument is a "reason code" (left as 0 since the reason strings are
  // separately loaded from the function strings).
  int func_int = static_cast<int>(func);
  return ERR_PACK(0, func_int, 0);
}

// Returns an Open-SSL friendly error code for the given reason code. Helper
// function meant for constructing an ERR_STRING_DATA object.
unsigned long OsslErrorCodeForReason(EngineErrorReason reason) {
  // The first argument to ERR_PACK will be packed in by OpenSSL, so leave it
  // as 0. The second argument is a "function code" (left as 0 since the reason
  // strings are separately loaded from the function strings). The second
  // argument is a "reason code" defined by our engine.
  int reason_int = static_cast<int>(reason);
  return ERR_PACK(0, 0, reason_int);
}

}  // namespace utils

}  // namespace error

}  // namespace engine

#endif  // ENGINE_ERROR_UTILS_ERROR_UTILS_H_
