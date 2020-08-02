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

#include <memory>
#include <utility>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace key_loader {
namespace {

// Creates an `OpenSslEcKey` from the PEM-encoded public key data loaded in
// `public_key_pem_bio`. Returns an error `Status` if unsuccessful.
//
// The `EC_KEY` struct contained within the returned `OpenSslEcKey` will have
// its public key parameters set to the values from the input PEM.
StatusOr<OpenSslEcKey> MakeEcKeyFromPublicKeyPemBio(OpenSslBio public_key_bio) {
  // OpenSSL provides two different `PEM_read_bio_*` functions for RSA public
  // keys: `PEM_read_bio_RSAPublicKey`, which interprets the input key material
  // as a PKCS#1 RSAPublicKey structure, and `PEM_read_bio_RSA_PUBKEY`, which
  // interprets the key material using the X.509 SubjectPublicKeyInfo encoding
  // (that is, standard PEM encoding). `PublicKey`s returned by Cloud KMS are
  // PEM-encoded, so we use the `PEM_read_bio_RSA_PUBKEY` function here.
  EC_KEY *ec_key = PEM_read_bio_EC_PUBKEY(public_key_bio.get(), nullptr,
                                          nullptr, nullptr);
  if (ec_key == nullptr) {
    return Status(StatusCode::kInternal, "PEM_read_bio_EC_PUBKEY failed");
  }

  // Returning a smart pointer here to simplify clean up of the `RSA` struct
  // in the error cases.
  return OpenSslEcKey(ec_key, &EC_KEY_free);
}

// Attaches the given `EC_KEY_METHOD` implementation to the `EC_KEY` struct so
// cryptography operations performed with the `EC_KEY` struct delegate to the
// `EC_KEY_METHOD`'s implementations. Returns an error `Status` if unsuccessful.
Status AttachEcKeyMethodToOpenSslEcKey(const EC_KEY_METHOD *method,
                                       EC_KEY *ec_key) {
  if (!EC_KEY_set_method(ec_key, method)) {
    return Status(StatusCode::kInternal, "EC_KEY_set_method failed");
  }
  return Status();
}

// Creates an `OpenSslEvpPkey` with the underlying pkey as the input
// `OpenSslEcKey`, or returns an error `Status`.
//
// The resulting `EVP_PKEY` will have `EVP_PKEY_type(pkey) == EVP_PKEY_EC_KEY`.
StatusOr<OpenSslEvpPkey> WrapEcKeyInEvpPkey(OpenSslEcKey ec_key) {
  // We initialize `EVP_PKEY` as a smart pointer even though we have to
  // eventually release it to OpenSSL as a raw pointer since it simplifies
  // cleanup in the error cases.
  auto evp_pkey = MakeEvpPkey();
  if (evp_pkey == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
  }

  // Once we assign the `RSA` struct to the `EVP_PKEY`, the `EVP_PKEY` assumes
  // ownership of `RSA` so we need to release the smart pointer here.
  if (!EVP_PKEY_assign_EC_KEY(evp_pkey.get(), ec_key.get())) {
    return Status(StatusCode::kInternal, "EVP_PKEY_assign_EC_KEY failed");
  }
  ec_key.release();
  return evp_pkey;
}

}  // namespace

StatusOr<OpenSslEvpPkey> MakeKmsEcEvpPkey(
    OpenSslBio public_key_bio,
    std::unique_ptr<::kmsengine::backing::CryptoKeyHandle> crypto_key_handle,
    const EC_KEY_METHOD *ec_key_method) {
  if (public_key_bio == nullptr ||
      crypto_key_handle == nullptr ||
      ec_key_method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "All arguments to MakeKmsEcEvpPkey must be non-null");
  }

  KMSENGINE_ASSIGN_OR_RETURN(
      auto ec_key, MakeEcKeyFromPublicKeyPemBio(std::move(public_key_bio)));

  // Important: `AttachEcKeyMethodToOpenSslEcKey` must be called on the `ec_key`
  // before any other initialization work is done to the `ec_key`. This is
  // because `AttachEcKeyMethodToOpenSslEcKey` calls `EC_KEY_set_method`, which
  // will call the engine's `EC_KEY_METHOD` `finish` function on `ec_key` before
  // setting `EC_KEY_METHOD`.
  //
  // If `AttachEcKeyMethodToOpenSslEcKey` is called after initialization work
  // is performed on the `ec_key`, then the initialization work done before the
  // call may be clobbered by `EC_KEY_set_method`'s call to `finish`. This can
  // (and has) lead to difficult-to-track down debugging issues since the
  // initialization work done after the call to `EC_KEY_set_method` will still
  // remain in the `ec_key` struct, the the initialization work done before the
  // call will have been removed.
  //
  // See https://github.com/googleinterns/cloud-kms-oss-tools/issues/83 for
  // more information.
  KMSENGINE_RETURN_IF_ERROR(
      AttachEcKeyMethodToOpenSslEcKey(ec_key_method, ec_key.get()));

  KMSENGINE_RETURN_IF_ERROR(
      AttachCryptoKeyHandleToOpenSslEcKey(std::move(crypto_key_handle),
                                          ec_key.get()));
  return WrapEcKeyInEvpPkey(std::move(ec_key));
}

}  // namespace key_loader
}  // namespace bridge
}  // namespace kmsengine
