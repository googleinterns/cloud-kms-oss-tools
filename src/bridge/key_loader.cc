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

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "src/backing/client/client.h"
#include "src/backing/client/crypto_key_version_algorithm.h"
#include "src/backing/client/public_key.h"
#include "src/backing/rsa/kms_rsa_key.h"
#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::backing::Client;
using ::kmsengine::backing::CryptoKeyVersionAlgorithm;
using ::kmsengine::backing::KmsRsaKey;
using ::kmsengine::backing::PublicKey;
using ::kmsengine::backing::RsaKey;

// Implementation of `KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR` that uses
// a unique temporary identifier for avoiding collision in the enclosing scope.
#define __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL(__lhs, __rhs, __name) \
  auto __name = (__rhs);                                                   \
  if (!__name.ok()) {                                                      \
    KMSENGINE_SIGNAL_ERROR(__name.status());                               \
    return nullptr;                                                          \
  }                                                                        \
  __lhs = std::move(__name.value());

// Signals an engine error to OpenSSL using the given StatusOr<T> and returns
// nullptr if it is an error status; otherwise, assigns the underlying
// StatusOr<T> value to the left-hand-side expression. Should be used only in
// engine-defined OpenSSL callbacks (for example, `RSA_METHOD` callbacks), since
// the returned "nullptr" value is intended for OpenSSL.
//
// The right-hand-side expression is guaranteed to be evaluated exactly once.
//
// Note: KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR expands into multiple
// statements; it cannot be used in a single statement (for example, within an
// `if` statement).
#define KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(__lhs, __rhs) \
  __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL(                     \
    __lhs, __rhs,                                                   \
    __KMSENGINE_MACRO_CONCAT(__status_or_value, __COUNTER__))

// Creates an `OpenSslRsa` from the input `PublicKey`.
//
// The `RSA` struct contained within the returned `OpenSslRsa` will have its
// public key parameters set to the values from the PEM-encoded `public_key`.
//
// Returns an error `Status` if unsuccessful.
StatusOr<OpenSslRsa> MakeOpenSslRsaFromPublicKey(PublicKey public_key) {
  // Generates a "memory buffer" using `BIO` (OpenSSL's representation of a
  // file or data stream) and loads the public key data into it.
  auto pem_pointer = static_cast<const void *>(public_key.pem().c_str());
  BIO *pem_stream = BIO_new_mem_buf(pem_pointer, public_key.pem().length());
  if (pem_stream == nullptr) {
    return Status(StatusCode::kInternal, "BIO_new_mem_buf failed");
  }

  // OpenSSL provides two different `PEM_read_bio_*` functions for RSA public
  // keys: `PEM_read_bio_RSAPublicKey`, which interprets the input key material
  // as a PKCS#1 RSAPublicKey structure, and `PEM_read_bio_RSA_PUBKEY`, which
  // interprets the key material using the X.509 SubjectPublicKeyInfo encoding
  // (that is, standard PEM encoding). `PublicKey`s returned by Cloud KMS are
  // PEM-encoded, so we use the `PEM_read_bio_RSA_PUBKEY` function here.
  RSA *rsa = PEM_read_bio_RSA_PUBKEY(pem_stream, nullptr, nullptr, nullptr);
  if (rsa == nullptr) {
    return Status(StatusCode::kInternal, "PEM_read_bio_RSA_PUBKEY failed");
  }

  // Returning a smart pointer here to simplify clean up of the `RSA` struct
  // in the error cases.
  return OpenSslRsa(rsa, &RSA_free);
}

// Helper function to create a `KmsRsaKey` and memory check it. Returns a
// non-null `RsaKey` unique pointer, or an error `Status`.
StatusOr<std::unique_ptr<RsaKey>> MakeKmsRsaKey(std::string key_resource_id,
                                                Client const& client) {
  auto kms_rsa_key = new KmsRsaKey(key_resource_id, client);
  if (kms_rsa_key == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
  }
  return std::unique_ptr<RsaKey>(kms_rsa_key);
}

// Creates an `OpenSslEvpPkey` with the underlying pkey as the input
// `OpenSslRsa`, or returns an error `Status`.
//
// The resulting `EVP_PKEY` will have `EVP_PKEY_type(pkey) == EVP_PKEY_RSA`.
StatusOr<OpenSslEvpPkey> MakeRsaEvpPkey(OpenSslRsa rsa) {
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

// Creates an `OpenSslEvpPkey` where the underlying `EVP_PKEY` has type
// `EVP_PKEY_RSA` from the input parameters.
//
// Since the `EVP_PKEY` has type `EVP_PKEY_RSA`, it will be backed by a `RSA`
// struct. The `RSA` struct will:
//
//    - Have its internal `RSA_METHOD` implementation point to the Cloud KMS
//      engine's implementation.
//
//    - Be backed by a `KmsRsaKey` that contains the input `key_resource_id`
//      and a reference to the `Client` from the input `engine_data`, such that
//      cryptography operations performed on the `RSA` struct will launch
//      Cloud KMS API requests for the given `key_resource_id`.
//
// If unsuccessful, returns an error `Status`.
StatusOr<OpenSslEvpPkey> MakeKmsRsaEvpPkey(PublicKey public_key,
                                           std::string key_resource_id,
                                           EngineData *engine_data) {
  KMSENGINE_ASSIGN_OR_RETURN(
      auto rsa, MakeOpenSslRsaFromPublicKey(public_key));
  KMSENGINE_ASSIGN_OR_RETURN(
      auto rsa_key, MakeKmsRsaKey(key_resource_id, engine_data->client()));
  KMSENGINE_RETURN_IF_ERROR(
      AttachRsaKeyToOpenSslRsa(std::move(rsa_key), rsa.get()));

  // Attach the engine `RSA_METHOD` implementation to the `RSA` struct so
  // cryptography operations performed with the `RSA` struct delegate to the
  // engine's implementations.
  if (!RSA_set_method(rsa.get(), engine_data->rsa_method())) {
    return Status(StatusCode::kInternal, "RSA_set_method failed");
  }

  return MakeRsaEvpPkey(std::move(rsa));
}

}  // namespace

EVP_PKEY *LoadPrivateKey(ENGINE *openssl_engine, const char *key_id,
                         UI_METHOD */*ui_method*/, void */*callback_data*/) {
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto engine_data, GetEngineDataFromOpenSslEngine(openssl_engine));

  std::cout << "data" << std::endl;
  std::cout << key_id << std::endl;

  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto public_key, engine_data->client().GetPublicKey(key_id));

  std::cout << "pem:       " << public_key.pem() << std::endl;
  std::cout << "algorithm: " << public_key.algorithm() << std::endl;

  OpenSslEvpPkey evp_pkey(nullptr, nullptr);
  switch (public_key.algorithm()) {
    case CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPss3072Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha512:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs2048Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs3072Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha512:
      {
        KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
            evp_pkey, MakeKmsRsaEvpPkey(public_key, key_id, engine_data));
        break;
      }
    case CryptoKeyVersionAlgorithm::kEcSignP256Sha256:
    case CryptoKeyVersionAlgorithm::kEcSignP384Sha384:
      {
        // TODO(zesp): Implement ECDSA. Can reuse `RsaKey` for this since the
        // backing layer is exactly the same; probably should refactor
        // `RsaKey` to be called some generic name instead.
        KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented,
            "ECDSA not yet implemented"));
        break;
      }
    default:
      {
        KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kFailedPrecondition,
            "Cloud KMS key had unsupported type " +
            CryptoKeyVersionAlgorithmToString(public_key.algorithm())));
        break;
      }
  }

  return evp_pkey.release();
}

#undef __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL
#undef KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR

}  // namespace bridge
}  // namespace kmsengine
