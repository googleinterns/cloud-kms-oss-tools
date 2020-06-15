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

#include "engine/error/error_handler.h"

#include <stdio.h>

#include "openssl/err.h"
#include "engine/error/error_strings.h"

namespace engine {

namespace error {

void ErrorHandler::LoadErrorStrings() {
  // This function should be idempotent after the engine has loaded.
  if (!strings_are_loaded_) {
    strings_are_loaded_ = true;

    // Register our custom error strings with OpenSSL.
    int library_error_code = this->GetErrorLibraryCode();
    ERR_load_strings(library_error_code,
      const_cast<ERR_STRING_DATA*>(kFunctionStrings));
    ERR_load_strings(library_error_code,
      const_cast<ERR_STRING_DATA*>(kReasonStrings));
  }
}

void ErrorHandler::UnloadErrorStrings() {
  if (strings_are_loaded_) {
    // Unregister our custom error strings with OpenSSL.
    ERR_unload_strings(ossl_library_error_code_,
      const_cast<ERR_STRING_DATA*>(kFunctionStrings));
    ERR_unload_strings(ossl_library_error_code_,
      const_cast<ERR_STRING_DATA*>(kReasonStrings));

    strings_are_loaded_ = false;
  }
}

void ErrorHandler::EngineErr(int function, int reason) {
  ErrEngineError(function, reason, OPENSSL_FILE, OPENSSL_LINE);
}

void ErrorHandler::ErrEngineError(int function, int reason, char *file, int line) {
  int library_error_code = this->GetErrorLibraryCode();
  ERR_PUT_error(library_error_code, function, reason, file, line);
}

int ErrorHandler::GetErrorLibraryCode() {
  if (ossl_library_error_code_ == 0) {
    // Ask OpenSSL for the next available library code.
    ossl_library_error_code_ = ERR_get_next_error_library();
  }
  return ossl_library_error_code_;
}

}  // namespace error

}  // namespace engine
