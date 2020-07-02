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

#include "src/bridge/error.h"

#include <stdio.h>

#include <openssl/err.h>

#include "src/backing/status/status.h"
#include "src/bridge/error_impl/error_strings.h"

namespace kmsengine {
namespace bridge {

// OpenSSL engines request a library code using ERR_get_next_error_library(3)
// with which they can register engine-specific, human-readable error strings
// with OpenSSL.
static const int kErrorLibraryCode = ERR_get_next_error_library();

void LoadErrorStringsIntoOpenSSL() {
  ERR_load_strings(GetLibraryCode(), error_impl::kLibraryStrings);
  ERR_load_strings(GetLibraryCode(), error_impl::kReasonStrings);
}

void UnloadErrorStringsFromOpenSSL() {
  ERR_unload_strings(GetLibraryCode(), error_impl::kLibraryStrings);
  ERR_unload_strings(GetLibraryCode(), error_impl::kReasonStrings);
}

void SignalErrorToOpenSSL(Status status, char *function_name, char *file_name,
                          int line_number) {
  // This signals to OpenSSL that an error occurred at all. The second argument
  // is a "function code"; we're ignoring that here by setting it to zero.
  //
  // This is similar to how OpenSSL 3.0.0 uses the `ERR_put_error` API - it
  // has completely removed function codes in favor of automatically passing
  // the function name from the `__func__` macro to `ERR_add_error_data`. The
  // engine uses this approach since function names aren't very useful to the
  // end-user anyways.
  //
  // See [https://github.com/openssl/openssl/pull/9072/
  // files#diff-1d66b2010eedc54493f1641feb6dc5eaR375-R381] for details.
  const auto kIgnoredFunctionCode = 0;
  ERR_put_error(GetLibraryCode(), kIgnoredFunctionCode,
                StatusCodeToInt(status.code()), file_name, line_number);

  // Associates the concatenation of the string arguments with the error code
  // we just added in `ERR_PUT_error`. The first argument is the number of
  // string arguments to concatenate.
  const auto kNumStrings = 4;
  auto error_message = status.message().c_str();
  ERR_add_error_data(kNumStrings, "Error occurred in ", function_name, ": ",
                                  error_message);
}

int GetLibraryCode() {
  return kErrorLibraryCode;
}

}  // namespace bridge
}  // namespace kmsengine
