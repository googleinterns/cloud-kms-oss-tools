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

#ifndef KMSENGINE_BACKING_CRYPTO_KEY_HANDLE_CRYPTO_KEY_HANDLE_H_
#define KMSENGINE_BACKING_CRYPTO_KEY_HANDLE_CRYPTO_KEY_HANDLE_H_

#include <string>

#include "src/backing/export_macros.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {

// Interface representing a handle to a Cloud KMS CryptoKeyVersion. Used to
// implement engine operations that usually involve accessing the private key
// without needing direct access to private key material.
//
// When `RSA` and `EC_KEY` objects are generated by the engine's bridge layer to
// represent a given CryptoKeyVersion, an `CryptoKeyHandle` for the
// CryptoKeyVersion should be instantiated and attached to the `RSA` (or
// `EC_KEY`) object. Then, when the bridge layer's cryptography implementations
// are called (specifically through the `RSA_METHOD` and `EC_KEY_METHOD`
// interfaces), the bridge layer should retrieve the `CryptoKeyHandle` attached
// to the calling `RSA` (or `EC_KEY`) object. From there, the bridge layer can
// call methods on the `CryptoKeyHandle` to perform operations with the
// underlying private key material.
//
// The bridge layer is also responsible for converting OpenSSL-native types from
// the `RSA_METHOD` arguments into engine-native types prior to calling the
// associated `CryptoKeyHandle` methods. This is because some conversions
// require knowledge of symbols from the OpenSSL library (which are not
// visible to the backing layer).
class KMSENGINE_EXPORT CryptoKeyHandle {
 public:
  virtual ~CryptoKeyHandle() = default;

  // `CryptoKeyHandle` is copyable and moveable.
  CryptoKeyHandle(const CryptoKeyHandle& other) = default;
  CryptoKeyHandle& operator=(const CryptoKeyHandle& other) = default;

  // Returns the Cloud KMS resource name for this `CryptoKeyHandle`.
  virtual std::string key_resource_id() const = 0;

  // Signs `digest_bytes` using the underlying private key material. Returns the
  // resulting signature as a `std::string`, or an error `Status`.
  //
  // Should be used in the engine's implementation of signing operations.
  virtual StatusOr<std::string> Sign(DigestCase digest_type,
                                     std::string digest_bytes) const = 0;

  // Returns the PEM-encoded public key of the underlying private key material,
  // or an error `Status`.
  virtual StatusOr<PublicKey> GetPublicKey() const = 0;
};

// Creates a `unique_ptr` containing a `CryptoKeyHandle` implementation.
KMSENGINE_EXPORT StatusOr<std::unique_ptr<CryptoKeyHandle>> MakeCryptoKeyHandle(
    std::string key_resource_id, Client const& client);

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CRYPTO_KEY_HANDLE_CRYPTO_KEY_HANDLE_H_
