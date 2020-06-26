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

#include "src/bridge/error/error_handler.h"

#include <stdio.h>

#include <openssl/err.h>

#include "src/bridge/error/error_strings.h"
#include "src/bridge/error/function_code.h"

namespace kmsengine {
namespace bridge {
namespace error {

static const std::vector<ERR_STRING_DATA> reason_strings = MakeReasonStrings();
static const std::vector<ERR_STRING_DATA> function_strings = MakeFunctionStrings();
static const OpenSSLLibraryCodeHandler code_handler;

void LoadErrorStringsIntoOpenSSL() {
  auto library_code = code_handler.GetLibraryCode();
  ERR_load_strings(library_code, function_strings.data());
  ERR_load_strings(library_code, reason_strings.data());
}

void UnloadErrorStringsFromOpenSSL() {
  auto library_code = code_handler.GetLibraryCode();
  ERR_unload_strings(library_code, function_strings.data());
  ERR_unload_strings(library_code, reason_strings.data());
}

void ErrEngineError(FunctionCode function, StatusCode reason, char *file, int line) {
  auto library_code = code_handler.GetLibraryCode();
  ERR_PUT_error(library_code,
                static_cast<std::underlying_type<FunctionCode>>(function),
                static_cast<std::underlying_type<StatusCode>>(reason),
                file, line);
}

}  // namespace error
}  // namespace bridge
}  // namespace kmsengine
