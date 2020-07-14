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

#include <openssl/rsa.h>

#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
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

}  // namespace

int Finish(RSA *rsa) {
  // Per the OpenSSL specification, the memory for the RSA struct itself should
  // not be freed by this function.
  auto rsa_key = GetRsaKeyFromOpenSslRsa(rsa);
  if (!rsa_key.ok()) return false;

  delete rsa_key.value();
  return AttachRsaKeyToOpenSslRsa(nullptr, rsa).ok();
}

int PublicEncrypt(int flen, const unsigned char *from, unsigned char *to,
                  RSA *rsa, int padding) {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented, __func__));
  return false;  // Unimplemented.
}

int PublicDecrypt(int flen, const unsigned char *from, unsigned char *to,
                  RSA *rsa, int padding) {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented, __func__));
  return false;  // Unimplemented.
}

int PrivateEncrypt(int flen, const unsigned char *from, unsigned char *to,
                   RSA *rsa, int padding) {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented, __func__));
  return false;  // Unimplemented.
}

int PrivateDecrypt(int flen, const unsigned char *from, unsigned char *to,
                   RSA *rsa, int padding) {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented, __func__));
  return false;  // Unimplemented.
}

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

int Verify(int type, const unsigned char *m, unsigned int m_length,
           const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa) {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented, __func__));
  return false;  // Unimplemented.
}

#undef __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL
#undef KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR

}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
