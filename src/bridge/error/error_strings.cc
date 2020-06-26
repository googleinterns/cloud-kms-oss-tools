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

#include "src/bridge/error/error_strings.h"

#include <openssl/err.h>

#include "src/backing/status/status_code.h"
#include "src/bridge/error/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error {

inline unsigned long PackReasonCode(StatusCode reason) {
  // The first argument to ERR_PACK will be packed in by OpenSSL, so leave it
  // as 0. The second argument is a "function code" (left as 0 since the reason
  // strings are separately loaded from the function strings). The second
  // argument is a "reason code" defined by our engine.
  return ERR_PACK(0, 0, static_cast<std::underlying_type<StatusCode>>(reason));
}

inline unsigned long PackFunctionCode(FunctionCode func) {
  // The first argument to ERR_PACK will be packed in by OpenSSL, so leave it
  // as 0. The second argument is a "function code" defined by our engine. The
  // third argument is a "reason code" (left as 0 since the reason strings are
  // separately loaded from the function strings).
  return ERR_PACK(0, static_cast<std::underlying_type<FunctionCode>>(func), 0);
}

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine
