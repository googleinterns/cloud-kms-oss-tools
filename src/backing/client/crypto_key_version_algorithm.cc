/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modifications copyright 2020 Google LLC
 *
 *    - Renamed namespaces and file includes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "src/backing/status/status.h"

#include <sstream>
#include <string>

namespace kmsengine {

std::string CryptoKeyVersionAlgorithmToString(CryptoKeyVersionAlgorithm algo) {
  switch (algo) {
    case CryptoKeyVersionAlgorithm::kAlgorithmUnspecified:
      return "ALGORITHM_UNSPECIFIED";
    case CryptoKeyVersionAlgorithm::kGoogleSymmetricEncryption:
      return "GOOGLE_SYMMETRIC_ENCRYPTION";
    case CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256:
      return "RSA_SIGN_PSS_2048_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaSignPss3072Sha256:
      return "RSA_SIGN_PSS_3072_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha256:
      return "RSA_SIGN_PSS_4096_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha512:
      return "RSA_SIGN_PSS_4096_SHA512";
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs2048Sha256:
      return "RSA_SIGN_PKCS_2048_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs3072Sha256:
      return "RSA_SIGN_PKCS_3072_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha256:
      return "RSA_SIGN_PKCS_4096_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha512:
      return "RSA_SIGN_PKCS_4096_SHA512";
    case CryptoKeyVersionAlgorithm::kRsaDecryptOaep2048Sha256:
      return "RSA_DECRYPT_OAEP_2048_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaDecryptOaep3072Sha256:
      return "RSA_DECRYPT_OAEP_3072_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha256:
      return "RSA_DECRYPT_OAEP_4096_SHA256";
    case CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha512:
      return "RSA_DECRYPT_OAEP_4096_SHA512";
    case CryptoKeyVersionAlgorithm::kEcSignP256Sha256:
      return "EC_SIGN_P256_SHA256";
    case CryptoKeyVersionAlgorithm::kEcSignP384Sha384:
      return "EC_SIGN_P384_SHA384";
    case CryptoKeyVersionAlgorithm::kExternalSymmetricEncryption:
      return "EXTERNAL_SYMMETRIC_ENCRYPTION";
    default:
      return "UNEXPECTED_STATUS_CODE=" + std::to_string(static_cast<int>(code));
  }
}

std::ostream& operator<<(std::ostream& os, CryptoKeyVersionAlgorithm code) {
  return os << CryptoKeyVersionAlgorithmToString(code);
}

}  // namespace kmsengine
