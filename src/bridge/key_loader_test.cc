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

#include <iostream>
#include <tuple>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "src/bridge/key_loader.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/testing_util/mock_client.h"
#include "src/testing_util/test_matchers.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/backing/rsa/kms_rsa_key.h"
#include "src/bridge/rsa/rsa.h"
#include "src/testing_util/openssl_assertions.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::backing::CryptoKeyVersionAlgorithm;
using ::kmsengine::backing::PublicKey;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockClient;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::StrEq;
using ::testing::Return;
using ::testing::AtLeast;
using ::testing::ValuesIn;
using ::testing::Combine;

// List of `CryptoKeyVersionAlgorithm`s valid for use in a RSA sign operation.
constexpr CryptoKeyVersionAlgorithm kRsaSignAlgorithms[] = {
  CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256,
  CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256,
  CryptoKeyVersionAlgorithm::kRsaSignPss3072Sha256,
  CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha256,
  CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha512,
  CryptoKeyVersionAlgorithm::kRsaSignPkcs2048Sha256,
  CryptoKeyVersionAlgorithm::kRsaSignPkcs3072Sha256,
  CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha256,
  CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha512,
};

// List of `CryptoKeyVersionAlgorithm`s valid for use in a EC sign operation.
constexpr CryptoKeyVersionAlgorithm kEcSignAlgorithms[] = {
  CryptoKeyVersionAlgorithm::kEcSignP256Sha256,
  CryptoKeyVersionAlgorithm::kEcSignP384Sha384,
};

// List of `CryptoKeyVersionAlgorithm`s that are unsupported by the engine.
constexpr CryptoKeyVersionAlgorithm kUnsupportedAlgorithms[] = {
  CryptoKeyVersionAlgorithm::kAlgorithmUnspecified,
  CryptoKeyVersionAlgorithm::kGoogleSymmetricEncryption,
  CryptoKeyVersionAlgorithm::kRsaDecryptOaep2048Sha256,
  CryptoKeyVersionAlgorithm::kRsaDecryptOaep3072Sha256,
  CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha256,
  CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha512,
  CryptoKeyVersionAlgorithm::kExternalSymmetricEncryption,
};

constexpr char kKeyResourceId[] = "resource_id";

const std::string kSampleSignatures[] = {
  // Random 2048-bit / 256-byte string.
  absl::HexStringToBytes(
      "650c9f2e6701e3fe73d3054904a9a4bbdb96733f1c4c743ef573ad6ac14c5a3bf8a4731f"
      "6e6276faea5247303677fb8dbdf24ff78e53c25052cdca87eecfee85476bcb8a05cb9a1e"
      "fef7cb87dd68223e117ce800ac46177172544757a487be32f5ab8fe0879fa8add78be465"
      "ea8f8d5acf977e9f1ae36d4d47816ea6ed41372b650c9f2e6701e3fe73d3054904a9a4bb"
      "db96733f1c4c743ef573ad6ac14c5a3bf8a4731f6e6276faea5247303677fb8dbdf24ff7"
      "8e53c25052cdca87eecfee85476bcb8a05cb9a1efef7cb87dd68223e117ce800ac461771"
      "72544757a487be32f5ab8fe0879fa8add78be465ea8f8d5acf977e9f1ae36d4d47816ea6"
      "ed41372b"),
  // Check that signing operations handle signatures containing null bytes.
  absl::HexStringToBytes(
      "foobar"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "barfoo"),
  // Check all null string.
  absl::HexStringToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000000000"),
  // Check some arbitrary short string.
  "my unique signature",
  // Check empty string.
  "",
};

// Just a random 2048-bit / 256-byte RSA public key.
constexpr char kPublicKey[] = "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
  "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"
  "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"
  "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"
  "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"
  "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"
  "wQIDAQAB\n"
  "-----END PUBLIC KEY-----\n";

// Byte size of the RSA key represented by `kPublicKey`. Used to check that
// our engine initializes the public key size parameters correctly when
// asked to load `kPublicKey`.
constexpr int kExpectedKeySize = 256;

TEST(KeyLoaderTest, HandlesBadEngineData) {
  EXPECT_THAT(InitExternalIndicies(), IsOk());

  // Should fail since no `EngineData` is attached to `ENGINE`.
  auto engine = MakeEngine();
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()), IsOk());
  EXPECT_OPENSSL_FAILURE(
      LoadPrivateKey(engine.get(), "resource_id", nullptr, nullptr),
      "ENGINE instance was not initialized with Cloud KMS data");

  FreeExternalIndicies();
}

class KeyLoaderTest : public ::testing::TestWithParam<
    std::tuple<CryptoKeyVersionAlgorithm, std::string>> {
 protected:
  KeyLoaderTest()
      : public_key_(PublicKey(kPublicKey, std::get<0>(GetParam()))),
        engine_(MakeEngine()),
        expected_signature_(std::get<1>(GetParam())) {}

  void SetUp() override {
    ASSERT_THAT(InitExternalIndicies(), IsOk());
  }

  void TearDown() override {
    FreeExternalIndicies();
  }

  PublicKey public_key() { return public_key_; }
  ENGINE *engine() { return engine_.get(); }
  std::string expected_signature() { return expected_signature_; }

 private:
  const PublicKey public_key_;
  const OpenSslEngine engine_;
  const std::string expected_signature_;
};

class RsaKeyLoaderTest : public KeyLoaderTest {
 protected:
  RsaKeyLoaderTest() : engine_data_(absl::make_unique<MockClient>(),
                                    rsa::MakeKmsRsaMethod()) {}

  // Initializes a `EngineData` struct and attaches it to `engine()` prior to
  // the `RsaKeyLoaderTest`. The `EngineData` struct is initialized with a
  // `MockClient` for testing purposes.
  void SetUp() override {
    KeyLoaderTest::SetUp();

    ON_CALL(mock_client(), GetPublicKey).WillByDefault(Return(public_key()));
    ON_CALL(mock_client(), AsymmetricSign)
        .WillByDefault(Return(expected_signature()));

    ASSERT_THAT(
        AttachEngineDataToOpenSslEngine(const_cast<EngineData*>(&engine_data()),
                                        engine()),
        IsOk());
  }

  // Returns a pointer to the `EngineData` used in the test.
  EngineData const& engine_data() { return engine_data_; }

  // Returns a reference to the `MockClient` attached to `engine_data()` so the
  // test can set custom expectations on the mock.
  MockClient const& mock_client() {
    return static_cast<MockClient const&>(engine_data().client());
  }

 private:
  const EngineData engine_data_;
};

INSTANTIATE_TEST_SUITE_P(
    RsaAlgorithmParameters, RsaKeyLoaderTest,
    Combine(ValuesIn(kRsaSignAlgorithms), ValuesIn(kSampleSignatures)));

TEST_P(RsaKeyLoaderTest, GeneratedKeyContainsInitializedRsaPublicKey) {
  EXPECT_CALL(mock_client(), GetPublicKey);
  EXPECT_CALL(mock_client(), AsymmetricSign).Times(AtLeast(1));

  auto evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));
  EXPECT_EQ(EVP_PKEY_size(evp_pkey), kExpectedKeySize);
  EXPECT_EQ(EVP_PKEY_id(evp_pkey), EVP_PKEY_RSA)
      << "Object ID of EVP_PKEY should be EVP_PKEY_RSA";

  auto rsa = EVP_PKEY_get1_RSA(evp_pkey);
  ASSERT_THAT(rsa, Not(IsNull()));
  EXPECT_EQ(RSA_get_method(rsa), engine_data().rsa_method())
      << "Underlying RSA struct of EVP_PKEY should be initialized with the "
         "EngineData's RSA_METHOD";

  auto rsa_key_or = GetRsaKeyFromOpenSslRsa(rsa);
  ASSERT_THAT(rsa_key_or, IsOk());

  auto kms_rsa_key = static_cast<backing::KmsRsaKey *>(rsa_key_or.value());
  EXPECT_THAT(kms_rsa_key->key_resource_id(), StrEq(kKeyResourceId))
      << "RsaKey should contain the key resource ID loaded in LoadPrivateKey";

  // OpenSSL recommends calling `RSA_sign` twice; once to get the
  // `signature_length` so the caller knows how much memory to allocate, and
  // the second time to get the actual signature. This test case reflects this
  // standard usage of the API.
  std::string digest = "digest";
  unsigned int signature_length;
  ASSERT_OPENSSL_SUCCESS(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), nullptr, &signature_length, rsa));

  std::string signature(signature_length, '\0');
  ASSERT_OPENSSL_SUCCESS(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(),
               reinterpret_cast<unsigned char *>(&signature[0]),
               &signature_length, rsa));

  EXPECT_THAT(signature, StrEq(expected_signature()))
      << "Client attached to EngineData should have been used in RSA_sign "
         "operation";

  RSA_free(rsa);
  EVP_PKEY_free(evp_pkey);
}

TEST_P(RsaKeyLoaderTest, GeneratedKeyWorksWithEvpDigestSignFunctions) {
  EXPECT_CALL(mock_client(), GetPublicKey);
  EXPECT_CALL(mock_client(), AsymmetricSign).Times(AtLeast(1));

  auto evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));
  EXPECT_EQ(EVP_PKEY_size(evp_pkey), kExpectedKeySize);
  EXPECT_EQ(EVP_PKEY_id(evp_pkey), EVP_PKEY_RSA)
      << "Object ID of EVP_PKEY should be EVP_PKEY_RSA";

  auto digest_context = MakeEvpDigestContext();
  ASSERT_OPENSSL_SUCCESS(EVP_DigestSignInit(digest_context.get(), nullptr,
                                            EVP_sha256(), nullptr, evp_pkey));

  std::string digest = "digest";
  ASSERT_OPENSSL_SUCCESS(
      EVP_DigestSignUpdate(digest_context.get(),
                           reinterpret_cast<unsigned char *>(&digest[0]),
                           digest.length()));

  // OpenSSL recommends calling `EVP_DigestSignFinal` twice; once to get the
  // `signature_length` so the caller knows how much memory to allocate, and
  // the second time to get the actual signature. This test case reflects this
  // standard usage of the API.
  size_t signature_length;
  ASSERT_OPENSSL_SUCCESS(
      EVP_DigestSignFinal(digest_context.get(), nullptr, &signature_length));

  std::string signature(signature_length, '\0');
  ASSERT_OPENSSL_SUCCESS(
      EVP_DigestSignFinal(digest_context.get(),
                          reinterpret_cast<unsigned char *>(&signature[0]),
                          &signature_length));

  // We reconstruct the string here because `signature.length()` is not
  // guaranteed to equal `signature_length`, and so this prevents us from
  // accidentally comparing against uninitialized bytes.
  std::string actual(signature, /*substring_start_index=*/0, signature_length);
  EXPECT_THAT(actual, StrEq(expected_signature()));
  EXPECT_EQ(signature_length, expected_signature().length());

  EVP_PKEY_free(evp_pkey);
}

class EcKeyLoaderTest : public KeyLoaderTest {};
INSTANTIATE_TEST_SUITE_P(
    EcAlgorithmParameters, EcKeyLoaderTest,
    Combine(ValuesIn(kEcSignAlgorithms), ValuesIn(kSampleSignatures)));

TEST_P(EcKeyLoaderTest, LoadPrivateKey) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).WillOnce(Return(public_key()));

  auto rsa_method = rsa::MakeKmsRsaMethod();
  ASSERT_OPENSSL_SUCCESS(ENGINE_set_RSA(engine(), rsa_method.get()));

  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine()), IsOk());

  EXPECT_OPENSSL_FAILURE(
      LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr),
      "ECDSA not yet implemented");

  delete engine_data;
}

class UnsupportedKeyLoaderTest : public KeyLoaderTest {};
INSTANTIATE_TEST_SUITE_P(
    UnsupportedAlgorithmParameters, UnsupportedKeyLoaderTest,
    Combine(ValuesIn(kUnsupportedAlgorithms), ValuesIn(kSampleSignatures)));

TEST_P(UnsupportedKeyLoaderTest, LoadPrivateKey) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).WillOnce(Return(public_key()));

  auto rsa_method = rsa::MakeKmsRsaMethod();
  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine()), IsOk());

  EXPECT_OPENSSL_FAILURE(
      LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr),
      "Cloud KMS key had unsupported type");

  delete engine_data;
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
