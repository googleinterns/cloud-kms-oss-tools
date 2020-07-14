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
  // Convert arguments to engine-native structures for convenience.
  //
  // These conversions need to take place within the bridge layer (as opposed
  // to the backing layer) since they refer to specific OpenSSL APIs.
  auto digest_type = ConvertOpenSslNidToDigestType(type);
  if (!digest_type.ok()) {
    KMSENGINE_SIGNAL_ERROR(digest_type.status());
    return false;
  }

  std::string digest(reinterpret_cast<const char *>(m), m_length);

  auto rsa_key = GetRsaKeyFromOpenSslRsa(rsa);
  if (!rsa_key.ok()) {
    KMSENGINE_SIGNAL_ERROR(rsa_key.status());
    return false;
  }

  // Delegate handling of the signing operation to the backing layer.
  auto result = rsa_key.value()->Sign(digest_type.value(), digest);
  if (!result.ok()) {
    KMSENGINE_SIGNAL_ERROR(result.status());
    return false;
  }

  // Output signature should be stored in `sigret` and its length in `siglen`.
  std::string signature = result.value();
  signature.copy(reinterpret_cast<char *>(sigret), signature.length());
  *siglen = signature.length();
  return true;
}

int Verify(int type, const unsigned char *m, unsigned int m_length,
           const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa) {
  KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kUnimplemented, __func__));
  return false;  // Unimplemented.
}

}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
