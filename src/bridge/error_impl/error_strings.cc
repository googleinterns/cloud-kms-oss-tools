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

#include "src/bridge/error_impl/error_strings.h"

#include <openssl/err.h>

#include "src/backing/status/status_code.h"
#include "src/bridge/error_impl/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error_impl {

constexpr unsigned long PackReasonCode(StatusCode code) {
  // The first argument is the "error library code" assigned to our engine by
  // OpenSSL, so leave as zero. The second argument is a "function code" (left
  // as 0 since the reason strings are separately loaded from the function
  // strings). The third argument is a "reason code" defined by our engine.
  return ERR_PACK(0, 0, StatusCodeToInt(code));
}

constexpr unsigned long PackFunctionCode(FunctionCode func) {
  // The first argument is the "error library code" assigned to our engine by
  // OpenSSL, so leave as zero. The second argument is a "function code" defined
  // by our engine. The third argument is a "reason code" (left as 0 since the
  // reason strings are separately loaded from the function strings).
  return ERR_PACK(0, FunctionCodeToInt(func), 0);
}

}  // namespace error_impl
}  // namespace bridge
}  // namespace kmsengine
