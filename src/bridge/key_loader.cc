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

#include <openssl/engine.h>

#include "src/backing/client/crypto_key_version_algorithm.h"
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

using ::kmsengine::backing::KmsRsaKey;
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

StatusOr<OpenSslBignum> MakeZeroBignum() {
  auto bignum = MakeBignum();
  if (bignum == nullptr) {
    return Status(StatusCode::kResourceExhausted, "no memory available");
  }
  BN_zero(bignum.get());
  return bignum;
}

StatusOr<OpenSslRsa> MakeRsaWithInitializedBignumFields() {
  // We initialize these as smart pointers even though we have to eventually
  // release them to OpenSSL as raw pointers since it simplifies cleanup in
  // the error cases.
  KMSENGINE_ASSIGN_OR_RETURN(auto n, MakeZeroBignum());
  BN_set_word(n.get(), 2048);

  KMSENGINE_ASSIGN_OR_RETURN(auto e, MakeZeroBignum());
  KMSENGINE_ASSIGN_OR_RETURN(auto d, MakeZeroBignum());
  KMSENGINE_ASSIGN_OR_RETURN(auto p, MakeZeroBignum());
  KMSENGINE_ASSIGN_OR_RETURN(auto q, MakeZeroBignum());
  KMSENGINE_ASSIGN_OR_RETURN(auto dmp1, MakeZeroBignum());
  KMSENGINE_ASSIGN_OR_RETURN(auto dmq1, MakeZeroBignum());
  KMSENGINE_ASSIGN_OR_RETURN(auto iqmp, MakeZeroBignum());

  auto rsa = MakeRsa();
  if (rsa == nullptr) {
    return Status(StatusCode::kResourceExhausted, "no memory available");
  }

  RSA_set0_key(rsa.get(), n.release(), e.release(), d.release());
  RSA_set0_factors(rsa.get(), p.release(), q.release());
  RSA_set0_crt_params(rsa.get(), dmp1.release(), dmq1.release(),
                      iqmp.release());
  return rsa;
}

// Creates an `OpenSslRsa` initialized with a `KmsRsaKey` and the `RSA_METHOD`
// attached to `engine_data, or returns an error `Status`.
//
// The underlying `KmsRsaKey` is initialized using the `Client` attached to
// `engine_data` and the input `key_resource_id`.
StatusOr<OpenSslRsa> MakeRsaWithKmsKey(EngineData *engine_data,
                                       std::string key_resource_id) {
  KMSENGINE_ASSIGN_OR_RETURN(auto rsa, MakeRsaWithInitializedBignumFields());
  auto rsa_key = std::unique_ptr<RsaKey>(new KmsRsaKey(key_resource_id,
                                                       engine_data->client()));
  if (rsa == nullptr || rsa_key == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
  }

  if (!RSA_set_method(rsa.get(), engine_data->rsa_method())) {
    return Status(StatusCode::kInternal, "RSA_set_method failed");
  }

  // If successful, pass ownership of `RsaKey` to the `RSA` struct.
  KMSENGINE_RETURN_IF_ERROR(AttachRsaKeyToOpenSslRsa(rsa_key.get(), rsa.get()));
  rsa_key.release();
  return rsa;
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

}  // namespace

EVP_PKEY *LoadPrivateKey(ENGINE *openssl_engine, const char *key_id,
                         UI_METHOD *ui_method, void *callback_data) {
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto engine_data, GetEngineDataFromOpenSslEngine(openssl_engine));
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto public_key, engine_data->client().GetPublicKey(key_id));

  using CryptoKeyVersionAlgorithm = backing::CryptoKeyVersionAlgorithm;
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
            auto kms_rsa, MakeRsaWithKmsKey(engine_data, key_id));
        KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
            auto kms_evp_pkey, MakeRsaEvpPkey(std::move(kms_rsa)));
        return kms_evp_pkey.release();
      }
    case CryptoKeyVersionAlgorithm::kEcSignP256Sha256:
    case CryptoKeyVersionAlgorithm::kEcSignP384Sha384:
      {
        // TODO(zesp): Implement ECDSA. Can reuse `RsaKey` for this since the
        // backing layer is exactly the same; probably should refactor
        // `RsaKey` to be called some generic name instead.
        KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented,
            "ECDSA not yet implemented"));
        return nullptr;
      }
    default:
      KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kFailedPrecondition,
          "Cloud KMS key had unsupported type " +
          CryptoKeyVersionAlgorithmToString(public_key.algorithm())));
      return nullptr;
  }
}

#undef __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL
#undef KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR

}  // namespace bridge
}  // namespace kmsengine
