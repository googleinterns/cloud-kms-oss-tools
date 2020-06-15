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

#ifndef ENGINE_ERROR_ERROR_STRINGS_H_
#define ENGINE_ERROR_ERROR_STRINGS_H_

#include <stdio.h>

#include "openssl/err.h"
#include "engine/error/error_codes.h"
#include "engine/error/utils/error_utils.h"

namespace engine {

namespace error {

// Associates each EngineFunction code with a human-readable string.
const ERR_STRING_DATA kFunctionStrings[] = {
  {utils::OsslErrorCodeForFunction(EngineFunction::kExampleFunction), "example_function"},
  {0, NULL},  // OpenSSL requires ERR_STRING_DATA to end with {0, NULL}
};

// Associates each EngineErrorReason code with a human-readable string.
const ERR_STRING_DATA kReasonStrings[] = {
  {utils::OsslErrorCodeForReason(EngineErrorReason::kExampleReason), "example reason"},
  {0, NULL},  // OpenSSL requires ERR_STRING_DATA to end with {0, NULL}
};

}  // namespace error

}  // namespace engine

#endif  // ENGINE_ERROR_ERROR_STRINGS_H_
