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

#ifndef KMSENGINE_BRIDGE_KEY_LOADER_EC_KEY_LOADER_H_
#define KMSENGINE_BRIDGE_KEY_LOADER_EC_KEY_LOADER_H_

#include <memory>

#include <openssl/ec.h>

#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace key_loader {

// Creates an `OpenSslEvpPkey` where the underlying `EVP_PKEY` has type
// `EVP_PKEY_EC` from the input parameters.
//
// Since the `EVP_PKEY` has type `EVP_PKEY_EC`, it will be backed by a `EC_KEY`
// struct. The `EC_KEY` struct will:
//
//    - Have its public key parameters populated by the PEM-encoded public key
//      data stored in `public_key_bio`.
//
//    - Have its internal `EC_KEY_METHOD` implementation point to the Cloud KMS
//      engine's implementation.
//
//    - Be backed by the input `CryptoKeyHandle` such that OpenSSL cryptography
//      operations performed on the `EC_KEY` struct will launch Cloud KMS API
//      requests for the given `key_resource_id` (when those operations are
//      supported by the engine).
//
// If unsuccessful, returns an error `Status`.
StatusOr<OpenSslEvpPkey> MakeKmsEcEvpPkey(
    OpenSslBio public_key_bio,
    std::unique_ptr<::kmsengine::backing::CryptoKeyHandle> crypto_key_handle,
    const EC_KEY_METHOD *ec_key_method);

}  // namespace key_loader
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_KEY_LOADER_EC_KEY_LOADER_H_
