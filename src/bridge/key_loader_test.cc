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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "absl/memory/memory.h"
#include "src/bridge/key_loader.h"
#include "src/bridge/engine_data.h"
#include "src/testing_util/mock_client.h"
#include "src/testing_util/test_matchers.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/backing/rsa/kms_rsa_key.h"
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

class KeyLoaderTest : public
    ::testing::TestWithParam<CryptoKeyVersionAlgorithm> {
 protected:
  KeyLoaderTest() : engine(MakeEngine()) {}

  void SetUp() override {
    EXPECT_THAT(InitExternalIndicies(), IsOk());

    const auto algorithm = GetParam();
    const auto public_key = PublicKey("my pem", algorithm);

    auto client = absl::make_unique<MockClient>();
    ON_CALL(*client, GetPublicKey).WillByDefault(Return(public_key));

    auto rsa_method = MakeRsaMethod("mock RSA_METHOD", 0);
    engine_data = new EngineData(std::move(client), std::move(rsa_method));

    ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine.get()),
                IsOk());
    ASSERT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), IsOk());
  }

  void TearDown() override {
    delete engine_data;
  }

  EngineData *engine_data;
  const OpenSslEngine engine;
};

INSTANTIATE_TEST_SUITE_P(RsaCryptoKeyVersionAlgorithmParameters,
                         KeyLoaderTest,
                         ValuesIn(kRsaSignAlgorithms));

TEST_P(KeyLoaderTest, LoadPrivateKey) {
  const auto kKeyResourceId = "resource_id";

  auto evp_pkey = LoadPrivateKey(engine.get(), kKeyResourceId, nullptr,
                                 nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));

  EXPECT_THAT(EVP_PKEY_id(evp_pkey), EVP_PKEY_RSA)
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

  delete rsa_key;
  RSA_free(rsa);
  EVP_PKEY_free(evp_pkey);
}

TEST(KeyLoaderTest, HandlesBadEngineData) {
  EXPECT_THAT(InitExternalIndicies(), IsOk());

  // Should fail since no `EngineData` is attached to `ENGINE`.
  auto engine = MakeEngine();
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()), IsOk());
  EXPECT_OPENSSL_FAILURE(
      LoadPrivateKey(engine.get(), "resource_id", nullptr, nullptr),
      "No Cloud KMS Client associated with ENGINE struct");
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
