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

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::backing::CryptoKeyVersionAlgorithm;
using ::kmsengine::backing::PublicKey;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockClient;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::Return;

class KeyLoaderTest : public ::testing::Test {
 protected:
  void SetUp() override {

  }

  void TearDown() override {

  }
};

TEST_F(KeyLoaderTest, LoadPrivateKey) {
  EXPECT_THAT(InitExternalIndicies(), IsOk());

  auto public_key = PublicKey("my pem",
                              CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256);

  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).Times(1).WillOnce(Return(public_key));

  auto rsa_method = MakeRsaMethod("mock RSA_METHOD", 0);
  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));

  auto engine = MakeEngine();
  EXPECT_THAT(AttachEngineDataToOpenSslEngine(engine_data, engine.get()),
              IsOk());
  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), IsOk());

  auto evp_pkey = LoadPrivateKey(engine.get(), "resource_id", nullptr, nullptr);
  ASSERT_THAT(evp_pkey, Not(IsNull()));

  auto rsa = EVP_PKEY_get1_RSA(evp_pkey);
  ASSERT_THAT(rsa, Not(IsNull()));
  EXPECT_EQ(RSA_get_method(rsa), engine_data->rsa_method());

  auto rsa_key = GetRsaKeyFromOpenSslRsa(rsa);
  ASSERT_THAT(rsa_key, IsOk());

  delete rsa_key.value();
  RSA_free(rsa);
  EVP_PKEY_free(evp_pkey);
  delete engine_data;
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
