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

#ifndef KMSENGINE_BACKING_CLIENT_CRYPTO_KEY_VERSION_ALGORITHM_H_
#define KMSENGINE_BACKING_CLIENT_CRYPTO_KEY_VERSION_ALGORITHM_H_

#include <type_traits>

namespace kmsengine {
namespace backing {

// Represents the algorithm used when performing cryptography operations with
// a given Cloud KMS key.
//
// Used in lieu of `google::cloud::kms::v1::CryptoKeyVersionAlgorithm` from the
// Cloud KMS API protobuf definitions since the bridge layer needs to refer to
// this resource directly and the bridge layer is not able to include external
// dependencies (such as the generated protobuf definitions).
//
// Underlying values should match the underlying values of the corresponding
// cases in `google::cloud::kms::v1::CryptoKeyVersionAlgorithm`; this allows for
// simple conversions between `CryptoKeyVersionAlgorithm` and its protobuf
// counterpart by using `static_cast`.
enum class CryptoKeyVersionAlgorithm : int {
  // Not specified.
  kAlgorithmUnspecified = 0,
  // Creates symmetric encryption keys.
  kGoogleSymmetricEncryption = 1,
  // RSASSA-PSS 2048 bit key with a SHA256 digest.
  kRsaSignPss2048Sha256 = 2,
  // RSASSA-PSS 3072 bit key with a SHA256 digest.
  kRsaSignPss3072Sha256 = 3,
  // RSASSA-PSS 4096 bit key with a SHA256 digest.
  kRsaSignPss4096Sha256 = 4,
  // RSASSA-PSS 4096 bit key with a SHA512 digest.
  kRsaSignPss4096Sha512 = 15,
  // RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
  kRsaSignPkcs2048Sha256 = 5,
  // RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
  kRsaSignPkcs3072Sha256 = 6,
  // RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
  kRsaSignPkcs4096Sha256 = 7,
  // RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
  kRsaSignPkcs4096Sha512 = 16,
  // RSAES-OAEP 2048 bit key with a SHA256 digest.
  kRsaDecryptOaep2048Sha256 = 8,
  // RSAES-OAEP 3072 bit key with a SHA256 digest.
  kRsaDecryptOaep3072Sha256 = 9,
  // RSAES-OAEP 4096 bit key with a SHA256 digest.
  kRsaDecryptOaep4096Sha256 = 10,
  // RSAES-OAEP 4096 bit key with a SHA512 digest.
  kRsaDecryptOaep4096Sha512 = 17,
  // ECDSA on the NIST P-256 curve with a SHA256 digest.
  kEcSignP256Sha256 = 12,
  // ECDSA on the NIST P-384 curve with a SHA384 digest.
  kEcSignP384Sha384 = 13,
  // Algorithm representing symmetric encryption by an external key manager.
  kExternalSymmetricEncryption = 18,
};

// Helper function for casting a `DigestCase` to its underlying type.
constexpr int CryptoKeyVersionAlgorithmToInt(CryptoKeyVersionAlgorithm algo) {
  return static_cast<
      std::underlying_type<CryptoKeyVersionAlgorithm>::type>(algo);
}

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_CRYPTO_KEY_VERSION_ALGORITHM_H_
