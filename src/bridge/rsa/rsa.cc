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

#include "src/bridge/rsa/rsa.h"

#include <openssl/rsa.h>

#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/bridge/nid_util/nid_util.h"

namespace kmsengine {
namespace bridge {
namespace rsa {
namespace {

// Implementation of `KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR` that uses
// a unique temporary identifier for avoiding collision in the enclosing scope.
#define __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL(__lhs, __rhs, __name) \
  auto __name = (__rhs);                                                   \
  if (!__name.ok()) {                                                      \
    KMSENGINE_SIGNAL_ERROR(__name.status());                               \
    return false;                                                          \
  }                                                                        \
  __lhs = std::move(__name.value());

// Signals an engine error to OpenSSL using the given StatusOr<T> and returns
// false if it is an error status; otherwise, assigns the underlying
// StatusOr<T> value to the left-hand-side expression. Should be used only in
// engine-defined OpenSSL callbacks (for example, `RSA_METHOD` callbacks), since
// the returned "false" value is intended for OpenSSL.
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

// Cleans up any internal structures associated with the input `rsa` struct
// (except for the RSA struct itself, which will be cleaned up by the OpenSSL
// library).
//
// Called when OpenSSL's `RSA_free` is called on `rsa`.
int Finish(RSA *rsa) {
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto rsa_key, GetRsaKeyFromOpenSslRsa(rsa));
  delete rsa_key;

  auto status = AttachRsaKeyToOpenSslRsa(nullptr, rsa);
  if (!status.ok()) KMSENGINE_SIGNAL_ERROR(status);
  return status.ok();
}

// Signs the message digest `m` of length `m_length` using the RSA private key
// represented by the OpenSSL RSA struct `rsa`. Then, stores the resulting
// signature in `sigret` and the signature size in `siglen`. `sigret`
// points to `RSA_size(rsa)` bytes of memory.
//
// Returns 1 on success; otherwise, returns 0.
int Sign(int type, const unsigned char *m, unsigned int m_length,
         unsigned char *sigret, unsigned int *siglen, const RSA *rsa) {
  // Convert arguments to engine-native structures for convenience. These
  // conversions need to take place within the bridge layer (as opposed to
  // letting the `RsaKey::Sign` method handling the conversions) since the
  // conversion functions refer to some OpenSSL API functions.
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto rsa_key, GetRsaKeyFromOpenSslRsa(rsa));
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto digest_type, ConvertOpenSslNidToDigestType(type));
  std::string digest(reinterpret_cast<const char *>(m), m_length);

  // Delegate handling of the signing operation to the backing layer.
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto signature, rsa_key->Sign(digest_type, digest));

  signature.copy(reinterpret_cast<char *>(sigret), signature.length());
  *siglen = signature.length();
  return true;
}

// Verifies that the signature `sigbuf` of size `siglen` matches a given
// message digest `m` of size `m_len`. `type` denotes the message digest
// algorithm that was used to generate the signature. `rsa` is the signer's
// public key represented with the OpenSSL RSA struct.
//
// Returns 1 if the signature is successfully verified; otherwise, returns 0.
int Verify(int type, const unsigned char *m, unsigned int m_length,
           const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa) {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented, __func__));
  return false;  // Unimplemented.
}

#undef __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL
#undef KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR

}  // namespace

OpenSslRsaMethod MakeKmsRsaMethod() {
  // RSA_FLAG_EXT_PKEY identifies that the RSA key is stored in external
  // hardware.
  auto rsa_method = MakeRsaMethod(kRsaMethodName, kRsaMethodFlags);
  if (!rsa_method) return OpenSslRsaMethod(nullptr, nullptr);

  // TODO(zesp): Investigate `PublicEncrypt`, `PublicDecrypt`, `PrivateEncrypt`,
  // and `PrivateDecrypt` are necessary given Sign and Verify.
  if (!RSA_meth_set_pub_enc(rsa_method.get(), nullptr) ||
      !RSA_meth_set_pub_dec(rsa_method.get(), nullptr) ||
      !RSA_meth_set_priv_enc(rsa_method.get(), nullptr) ||
      !RSA_meth_set_priv_dec(rsa_method.get(), nullptr) ||
      !RSA_meth_set_sign(rsa_method.get(), Sign) ||
      !RSA_meth_set_verify(rsa_method.get(), Verify) ||
      // `mod_exp` and `bn_mod_exp` are called by the default OpenSSL RSA
      // method. They are NULL since we're overriding the default RSA
      // methods anyways.
      !RSA_meth_set_mod_exp(rsa_method.get(), nullptr) ||
      !RSA_meth_set_bn_mod_exp(rsa_method.get(), nullptr) ||
      // `keygen` is NULL since key management functions are out of scope of
      // the Cloud KMS engine.
      !RSA_meth_set_keygen(rsa_method.get(), nullptr) ||
      // `init` is called in response to the OpenSSL application calling
      // `RSA_new`. Initialization work is delegated to the EVP_PKEY loader, so
      // it is NULL.
      !RSA_meth_set_init(rsa_method.get(), nullptr) ||
      !RSA_meth_set_finish(rsa_method.get(), Finish)) {
    return OpenSslRsaMethod(nullptr, nullptr);
  }

  return rsa_method;
}

}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
