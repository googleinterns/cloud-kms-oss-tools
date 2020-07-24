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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "absl/memory/memory.h"
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
using ::testing::ValuesIn;

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

constexpr CryptoKeyVersionAlgorithm kEcSignAlgorithms[] = {
  CryptoKeyVersionAlgorithm::kEcSignP256Sha256,
  CryptoKeyVersionAlgorithm::kEcSignP384Sha384,
};

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
const std::string kSignature = "signature";

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

class KeyLoaderTest : public
    ::testing::TestWithParam<CryptoKeyVersionAlgorithm> {
 protected:
  KeyLoaderTest()
      : public_key_(PublicKey("my pem", GetParam())),
        engine_(MakeEngine()) {}

  void SetUp() override {
    ASSERT_THAT(InitExternalIndicies(), IsOk());
  }

  void TearDown() override {
    FreeExternalIndicies();
  }

  PublicKey public_key() { return public_key_; }
  ENGINE *engine() { return engine_.get(); }

 private:
  PublicKey public_key_;
  OpenSslEngine engine_;
};

class RsaKeyLoaderTest : public KeyLoaderTest {};
INSTANTIATE_TEST_SUITE_P(RsaAlgorithmParameters, RsaKeyLoaderTest,
                         ValuesIn(kRsaSignAlgorithms));

TEST_P(RsaKeyLoaderTest, LoadPrivateKey) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).WillOnce(Return(public_key()));
  EXPECT_CALL(*client, AsymmetricSign)
      .WillRepeatedly(Return(kSignature));

  auto rsa_method = rsa::MakeKmsRsaMethod();
  ASSERT_OPENSSL_SUCCESS(ENGINE_set_RSA(engine(), rsa_method.get()));

  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine()), IsOk());

  auto evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));
  EXPECT_EQ(EVP_PKEY_id(evp_pkey), EVP_PKEY_RSA)
      << "Object ID of EVP_PKEY should be EVP_PKEY_RSA";

  auto rsa = EVP_PKEY_get1_RSA(evp_pkey);
  ASSERT_THAT(rsa, Not(IsNull()));
  EXPECT_EQ(RSA_get_method(rsa), engine_data->rsa_method())
      << "Underlying RSA struct of EVP_PKEY should be initialized with the "
         "EngineData's RSA_METHOD";

  auto rsa_key_or = GetRsaKeyFromOpenSslRsa(rsa);
  ASSERT_THAT(rsa_key_or, IsOk());
  auto rsa_key = rsa_key_or.value();
  EXPECT_THAT(static_cast<backing::KmsRsaKey*>(rsa_key)->key_resource_id(),
              StrEq(kKeyResourceId))
      << "RsaKey should contain the key resource ID loaded in LoadPrivateKey";

  unsigned char digest[] = "sample digest";
  unsigned int digest_length = std::strlen(reinterpret_cast<char *>(digest));

  unsigned int signature_length;
  ASSERT_OPENSSL_SUCCESS(RSA_sign(NID_sha256, digest, digest_length, nullptr,
                                  &signature_length, rsa));

  std::string signature(signature_length, '\0');
  ASSERT_OPENSSL_SUCCESS(
      RSA_sign(NID_sha256, digest, digest_length,
               reinterpret_cast<unsigned char *>(&signature[0]),
               &signature_length, rsa));

  EXPECT_THAT(signature, StrEq(kSignature))
      << "Client attached to EngineData should have been used in RSA_sign "
         "operation";

  RSA_free(rsa);
  EVP_PKEY_free(evp_pkey);
  delete engine_data;
}

TEST_P(RsaKeyLoaderTest, EvpPkeyTest) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).WillOnce(Return(public_key()));
  EXPECT_CALL(*client, AsymmetricSign)
      .WillOnce(Return(kSignature));

  auto rsa_method = rsa::MakeKmsRsaMethod();
  ASSERT_OPENSSL_SUCCESS(ENGINE_set_RSA(engine(), rsa_method.get()));

  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine()), IsOk());

  auto evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));

  ASSERT_OPENSSL_SUCCESS(EVP_PKEY_CTX_new(evp_pkey, engine()));
}

TEST_P(RsaKeyLoaderTest, EvpPkeyFull) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).WillOnce(Return(public_key()));
  EXPECT_CALL(*client, AsymmetricSign)
      .WillOnce(Return(kSignature));

  auto rsa_method = rsa::MakeKmsRsaMethod();
  ASSERT_OPENSSL_SUCCESS(ENGINE_set_RSA(engine(), rsa_method.get()));

  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine()), IsOk());

  auto evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));

  auto sign_context = MakeEvpPkeyContext(evp_pkey, engine());
  ASSERT_THAT(sign_context, Not(IsNull()));

  ASSERT_OPENSSL_SUCCESS(EVP_PKEY_sign_init(sign_context.get()));
  ASSERT_OPENSSL_SUCCESS(EVP_PKEY_CTX_set_signature_md(sign_context.get(),
                                                       EVP_sha256()));

  std::string digest = "digest";
  size_t signature_length;
  ASSERT_OPENSSL_SUCCESS(
      EVP_PKEY_sign(sign_context.get(), nullptr, &signature_length,
                    reinterpret_cast<unsigned char *>(&digest[0]),
                    digest.length()));

  std::cout << signature_length << std::endl;

  std::string signature(signature_length, '\0');
  ASSERT_OPENSSL_SUCCESS(
      EVP_PKEY_sign(sign_context.get(),
                    reinterpret_cast<unsigned char *>(&signature[0]),
                    &signature_length,
                    reinterpret_cast<unsigned char *>(&digest[0]),
                    digest.length()));

  std::cout << signature << std::endl;

  sign_context.reset();
  EVP_PKEY_free(evp_pkey);
  delete engine_data;
}

TEST_P(RsaKeyLoaderTest, EvpMdPkeyFull) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).WillOnce(Return(public_key()));
  EXPECT_CALL(*client, AsymmetricSign)
      .WillOnce(Return(kSignature));

  auto rsa_method = rsa::MakeKmsRsaMethod();
  ASSERT_OPENSSL_SUCCESS(ENGINE_set_RSA(engine(), rsa_method.get()));

  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine()), IsOk());

  auto evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));

  std::cout << "Size: " << EVP_PKEY_size(evp_pkey) << std::endl;

  auto context = EVP_MD_CTX_new();
  ASSERT_OPENSSL_SUCCESS(
      EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, evp_pkey));

  std::string digest = "digest";
  ASSERT_OPENSSL_SUCCESS(
      EVP_DigestSignUpdate(context,
                           reinterpret_cast<unsigned char *>(&digest[0]),
                           digest.length()));

  // OpenSSL recommends calling `EVP_DigestSignFinal` twice; once to get the
  // `signature_length` so the caller knows how much memory to allocate, and
  // the second time to get the actual signature. This test case reflects this
  // standard usage of the API.
  size_t signature_length;
  ASSERT_OPENSSL_SUCCESS(
      EVP_DigestSignFinal(context, nullptr, &signature_length));

  std::string signature(signature_length, '\0');
  ASSERT_OPENSSL_SUCCESS(
      EVP_DigestSignFinal(context,
                          reinterpret_cast<unsigned char *>(&signature[0]),
                          &signature_length));

  EXPECT_THAT(signature, StrEq(kSignature));
  EXPECT_EQ(signature_length, kSignature.length());

  EVP_PKEY_free(evp_pkey);
  delete engine_data;
}

class EcKeyLoaderTest : public KeyLoaderTest {};
INSTANTIATE_TEST_SUITE_P(EcAlgorithmParameters,
                         EcKeyLoaderTest,
                         ValuesIn(kEcSignAlgorithms));

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
INSTANTIATE_TEST_SUITE_P(UnsupportedAlgorithmParameters,
                         UnsupportedKeyLoaderTest,
                         ValuesIn(kUnsupportedAlgorithms));

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
