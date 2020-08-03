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

#include "src/bridge/memory_util/openssl_bio.h"

#include <string>

#include <openssl/bio.h>

#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {

StatusOr<OpenSslBio> MakeOpenSslBioFromString(const void *data, int length) {
  BIO *pem_stream = BIO_new_mem_buf(data, length);
  if (pem_stream == nullptr) {
    return Status(StatusCode::kInternal, "BIO_new_mem_buf failed");
  }

  // Second parameter of `OpenSslBio` specifies the deleter function that should
  // be called on the underlying BIO pointer when the `OpenSslBio` smart pointer
  // goes out of scope.
  return OpenSslBio(pem_stream, &BIO_free);
}

}  // namespace bridge
}  // namespace kmsengine
