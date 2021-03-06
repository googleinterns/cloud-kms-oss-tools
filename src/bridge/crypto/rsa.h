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

#ifndef KMSENGINE_BRIDGE_CRYPTO_RSA_H_
#define KMSENGINE_BRIDGE_CRYPTO_RSA_H_

#include <openssl/rsa.h>

#include "src/bridge/memory_util/openssl_structs.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace bridge {
namespace crypto {

// Allocates memory for and initializes an OpenSSL `RSA_METHOD` struct with
// pointers to the Cloud KMS engine RSA implementations.
StatusOr<OpenSslRsaMethod> MakeKmsRsaMethod();

}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_CRYPTO_RSA_H_
