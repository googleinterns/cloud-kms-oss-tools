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

#include <string>

#include "src/backing/status/status_or.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {

// A wrapper around `BIO_new_mem_buf` that instantiates a `BIO` (OpenSSL's
// abstraction for a stream of data) and loads the given string `bytes` into the
// stream.
//
// The memory stored in `data` must outlive the `BIO` instance, since
// `MakeOpenSslMemoryBufferBio` is implemented with `BIO_new_mem_buf` which only
// makes a shallow copy of the `data`. The behavior of the output `BIO` is
// undefined if the memory in `data` goes out of scope.
//
// Returns the `BIO` as a unique pointer that calls `BIO_free` when the pointer
// goes out of scope, or returns an error `Status` if unsuccessful.
StatusOr<OpenSslBio> MakeOpenSslMemoryBufferBio(const void *data, int length);

}  // namespace bridge
}  // namespace kmsengine
