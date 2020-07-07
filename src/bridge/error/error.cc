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

#include <iostream>

#include <openssl/err.h>

#include "src/backing/status/status.h"
#include "src/bridge/error/error_strings.h"

namespace kmsengine {
namespace bridge {

Status LoadErrorStringsIntoOpenSSL() {
  if (!ERR_load_strings(0, error_impl::kLibraryStrings) ||
      !ERR_load_strings(GetErrorLibraryId(), error_impl::kReasonStrings)) {
    return Status(StatusCode::kInternal, "ERR_load_strings failed");
  }
  return Status();
}

Status UnloadErrorStringsFromOpenSSL() {
  if (!ERR_unload_strings(0, error_impl::kLibraryStrings) ||
      !ERR_unload_strings(GetErrorLibraryId(), error_impl::kReasonStrings)) {
    return Status(StatusCode::kInternal, "ERR_unload_strings failed");
  }
  return Status();
}

void SignalErrorToOpenSSL(Status status, const char *function_name,
                          const char *file_name, int line_number) {
  // `ERR_put_error` signals to OpenSSL that an error occurred. The second
  // argument is a "function code"; we're ignoring that here by setting it to
  // zero.
  //
  // This is similar to how OpenSSL 3.0.0 uses the `ERR_put_error` API - it
  // has completely removed function codes in favor of automatically passing
  // the function name from the `__func__` macro to `ERR_add_error_data`. We
  // chose this approach since function names aren't very useful to the
  // end-user anyways.
  //
  // See https://github.com/googleinterns/cloud-kms-oss-tools/issues/34 for
  // discussion and examples from the OpenSSL 3.0.0 repository.
  ERR_PUT_error(GetErrorLibraryId(), /*func=*/0,
                StatusCodeToInt(status.code()), file_name, line_number);

  // Associates the concatenation of the string arguments with the error code
  // we just added in `ERR_PUT_error`. The first argument is the number of
  // string arguments to concatenate.
  ERR_add_error_data(/*num_strings=*/4, "Error occurred in ", function_name,
                     ": ", status.message().c_str());
}

int GetErrorLibraryId() {
  // OpenSSL engines request a library code using ERR_get_next_error_library(3)
  // with which they can register engine-specific, human-readable error strings
  // with OpenSSL.
  static const int kErrorLibraryCode = ERR_get_next_error_library();
  return kErrorLibraryCode;
}

}  // namespace bridge
}  // namespace kmsengine
