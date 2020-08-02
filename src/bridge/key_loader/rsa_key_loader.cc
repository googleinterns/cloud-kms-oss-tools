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

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace key_loader {
namespace {

// Creates an `OpenSslRsa` from the PEM-encoded public key data loaded in
// `public_key_bio`. Returns an error `Status` if unsuccessful.
//
// The `RSA` struct contained within the returned `OpenSslRsa` will have its
// public key parameters set to the values from the input PEM.
StatusOr<OpenSslRsa> MakeRsaFromPublicKeyPemBio(OpenSslBio public_key_bio) {
  // OpenSSL provides two different `PEM_read_bio_*` functions for RSA public
  // keys: `PEM_read_bio_RSAPublicKey`, which interprets the input key material
  // as a PKCS#1 RSAPublicKey structure, and `PEM_read_bio_RSA_PUBKEY`, which
  // interprets the key material using the X.509 SubjectPublicKeyInfo encoding
  // (that is, standard PEM encoding). `PublicKey`s returned by Cloud KMS are
  // PEM-encoded, so we use the `PEM_read_bio_RSA_PUBKEY` function here.
  //
  // `PEM_read_bio_RSA_PUBKEY` does not assume ownership of the input `BIO`
  // struct. Thus, the caller of `PEM_read_bio_RSA_PUBKEY` is responsible for
  // cleaning up the `BIO`. Here, we let C++'s smart pointer magic clean up
  // `public_key_bio` when it goes out of scope at the end of the function.
  RSA *rsa = PEM_read_bio_RSA_PUBKEY(public_key_bio.get(), nullptr,
                                     nullptr, nullptr);
  if (rsa == nullptr) {
    return Status(StatusCode::kInternal, "PEM_read_bio_RSA_PUBKEY failed");
  }

  // Returning a smart pointer here to simplify clean up of the `RSA` struct
  // in the error cases.
  return OpenSslRsa(rsa, &RSA_free);
}

Status AttachRsaMethodToOpenSslRsa(const RSA_METHOD *rsa_method, RSA *rsa) {
  // Attach the engine `RSA_METHOD` implementation to the `RSA` struct so
  // cryptography operations performed with the `RSA` struct delegate to the
  // engine's implementations.
  if (!RSA_set_method(rsa, rsa_method)) {
    return Status(StatusCode::kInternal, "RSA_set_method failed");
  }

  // `RSA_set_flags` has no return value and always succeeds.
  RSA_set_flags(rsa, RSA_meth_get_flags(rsa_method));
  return Status();
}

// Creates an `OpenSslEvpPkey` with the underlying pkey as the input
// `OpenSslRsa`, or returns an error `Status`.
//
// The resulting `EVP_PKEY` will have `EVP_PKEY_type(pkey) == EVP_PKEY_RSA`.
StatusOr<OpenSslEvpPkey> WrapRsaInEvpPkey(OpenSslRsa rsa) {
  // We initialize `EVP_PKEY` as a smart pointer even though we have to
  // eventually release it to OpenSSL as a raw pointer since it simplifies
  // cleanup in the error cases.
  auto evp_pkey = MakeEvpPkey();
  if (evp_pkey == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
  }

  // Once we assign the `RSA` struct to the `EVP_PKEY`, the `EVP_PKEY` assumes
  // ownership of `RSA` so we need to release the smart pointer here.
  if (!EVP_PKEY_assign_RSA(evp_pkey.get(), rsa.get())) {
    return Status(StatusCode::kInternal, "EVP_PKEY_assign_RSA failed");
  }
  rsa.release();
  return evp_pkey;
}

}  // namespace

StatusOr<OpenSslEvpPkey> MakeKmsRsaEvpPkey(
    OpenSslBio public_key_bio,
    std::unique_ptr<::kmsengine::backing::CryptoKeyHandle> crypto_key_handle,
    const RSA_METHOD *rsa_method) {
  if (public_key_bio == nullptr ||
      crypto_key_handle == nullptr ||
      rsa_method == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "All arguments to MakeKmsRsaEvpPkey must be non-null");
  }

  KMSENGINE_ASSIGN_OR_RETURN(
      auto rsa, MakeRsaFromPublicKeyPemBio(std::move(public_key_bio)));

  // Important: `AttachRsaMethodToOpenSslRsa` must be called on the `rsa`
  // before any other initialization work is done to the `rsa`. This is
  // because `AttachRsaMethodToOpenSslRsa` calls `RSA_set_method`, which
  // will call the engine's `RSA_METHOD` `finish` function on `rsa` before
  // setting `RSA_METHOD`.
  //
  // If `AttachRsaMethodToOpenSslRsa` is called after initialization work
  // is performed on the `rsa`, then the initialization work done before the
  // call may be clobbered by `RSA_set_method`'s call to `finish`. This can
  // (and has) lead to difficult-to-track down debugging issues since the
  // initialization work done after the call to `RSA_set_method` will still
  // remain in the `rsa` struct, the the initialization work done before the
  // call will have been removed.
  KMSENGINE_RETURN_IF_ERROR(
      AttachRsaMethodToOpenSslRsa(rsa_method, rsa.get()));

  KMSENGINE_RETURN_IF_ERROR(
      AttachCryptoKeyHandleToOpenSslRsa(std::move(crypto_key_handle),
                                        rsa.get()));
  return WrapRsaInEvpPkey(std::move(rsa));
}

}  // namespace key_loader
}  // namespace bridge
}  // namespace kmsengine
