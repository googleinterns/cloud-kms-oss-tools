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

#include <set>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "google/cloud/kms/v1/resources.pb.h"
#include "src/backing/client/crypto_key_version_algorithm.h"

namespace kmsengine {
namespace backing {
namespace {

using ::testing::ValuesIn;

using CryptoKeyVersion = google::cloud::kms::v1::CryptoKeyVersion;

// Mapping between `DigestCase` cases and their protobuf equivalents.
struct CorrespondingCryptoKeyVersionAlgorithm {
  CryptoKeyVersionAlgorithm actual;
  google::cloud::kms::v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm proto;
} const kCryptoKeyVersionAlgorithmMapping[]{
    {CryptoKeyVersionAlgorithm::kAlgorithmUnspecified,
        CryptoKeyVersion::CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED},
    {CryptoKeyVersionAlgorithm::kGoogleSymmetricEncryption,
        CryptoKeyVersion::GOOGLE_SYMMETRIC_ENCRYPTION},
    {CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256,
        CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaSignPss3072Sha256,
        CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha256,
        CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha512,
        CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512},
    {CryptoKeyVersionAlgorithm::kRsaSignPkcs2048Sha256,
        CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaSignPkcs3072Sha256,
        CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha256,
        CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha512,
        CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512},
    {CryptoKeyVersionAlgorithm::kRsaDecryptOaep2048Sha256,
        CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaDecryptOaep3072Sha256,
        CryptoKeyVersion::RSA_DECRYPT_OAEP_3072_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha256,
        CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256},
    {CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha512,
        CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA512},
    {CryptoKeyVersionAlgorithm::kEcSignP256Sha256,
        CryptoKeyVersion::EC_SIGN_P256_SHA256},
    {CryptoKeyVersionAlgorithm::kEcSignP384Sha384,
        CryptoKeyVersion::EC_SIGN_P384_SHA384},
    {CryptoKeyVersionAlgorithm::kExternalSymmetricEncryption,
        CryptoKeyVersion::EXTERNAL_SYMMETRIC_ENCRYPTION},
};

class CryptoKeyVersionAlgorithmTest : public
    testing::TestWithParam<CorrespondingCryptoKeyVersionAlgorithm> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(CryptoKeyVersionAlgorithmParameters,
                         CryptoKeyVersionAlgorithmTest,
                         ValuesIn(kCryptoKeyVersionAlgorithmMapping));

TEST_P(CryptoKeyVersionAlgorithmTest, UnderlyingValueMatchesProtoValues) {
  auto mapping = GetParam();
  EXPECT_EQ(CryptoKeyVersionAlgorithmToInt(mapping.actual), mapping.proto);
}

TEST(CryptoKeyVersionAlgorithmTest, ToStringIsOneToOne) {
  const std::vector<CryptoKeyVersionAlgorithm> kAlgorithms = {
    CryptoKeyVersionAlgorithm::kAlgorithmUnspecified,
    CryptoKeyVersionAlgorithm::kGoogleSymmetricEncryption,
    CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256,
    CryptoKeyVersionAlgorithm::kRsaSignPss3072Sha256,
    CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha256,
    CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha512,
    CryptoKeyVersionAlgorithm::kRsaSignPkcs2048Sha256,
    CryptoKeyVersionAlgorithm::kRsaSignPkcs3072Sha256,
    CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha256,
    CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha512,
    CryptoKeyVersionAlgorithm::kRsaDecryptOaep2048Sha256,
    CryptoKeyVersionAlgorithm::kRsaDecryptOaep3072Sha256,
    CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha256,
    CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha512,
    CryptoKeyVersionAlgorithm::kEcSignP256Sha256,
    CryptoKeyVersionAlgorithm::kEcSignP384Sha384,
    CryptoKeyVersionAlgorithm::kExternalSymmetricEncryption,
  };

  std::set<std::string> used_strings;
  for (auto algorithm : kAlgorithms) {
    auto actual = CryptoKeyVersionAlgorithmToString(algorithm);
    used_strings.insert(actual);
  }

  EXPECT_EQ(used_strings.size(), kAlgorithms.size());
}

TEST(CryptoKeyVersionAlgorithmTest, HandlesInvalidEnums) {
  EXPECT_EQ("UNEXPECTED_CRYPTO_KEY_VERSION_ALGORITHM=42",
            CryptoKeyVersionAlgorithmToString(
                static_cast<CryptoKeyVersionAlgorithm>(42)));
}

}  // namespace
}  // namespace backing
}  // namespace kmsengine
