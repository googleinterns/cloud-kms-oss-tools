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

#ifndef KMSENGINE_BRIDGE_CRYPTO_COMMON_H_
#define KMSENGINE_BRIDGE_CRYPTO_COMMON_H_

#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"

namespace kmsengine {
namespace bridge {
namespace crypto {

// `Sign` implementation for both `EC_KEY_METHOD` and `RSA_METHOD`.
Status CommonSign(int type, const unsigned char *digest_bytes,
                  int digest_length, unsigned char *signature_return,
                  unsigned int *signature_length,
                  const backing::CryptoKeyHandle *crypto_key_handle);

}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_CRYPTO_COMMON_H_
