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
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "absl/memory/memory.h"
#include "src/bridge/memory_util/openssl_bio.h"
#include "src/bridge/key_loader/ec_key_loader.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/testing_util/mock_crypto_key_handle.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace key_loader {
namespace {

using ::testing::Not;
using ::testing::NotNull;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockCryptoKeyHandle;

// A random 2048-bit / 256-byte ECDSA public key, encoded in PEM format.
constexpr char kEcdsaPublicKey[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xOUetsCa8EfOlDEBAfREhJqspDo\n"
  "yEh6Szz2in47Tv5n52m9dLYyPCbqZkOB5nTSqtscpkQD/HpykCggvx09iQ==\n"
  "-----END PUBLIC KEY-----\n";

// Fixture for testing `EcKeyLoader`.
class EcKeyLoaderTest : public ::testing::Test {
  void SetUp() override {
    ASSERT_THAT(InitExternalIndicies(), IsOk());
  }

  void TearDown() override {
    FreeExternalIndicies();
  }
};

TEST_F(EcKeyLoaderTest, MakeKmsRsaEvpPkey) {
  auto public_key_pem_bio_or = MakeOpenSslBioFromString(
      kEcdsaPublicKey, sizeof(kEcdsaPublicKey));
  ASSERT_THAT(public_key_pem_bio_or, IsOk());

  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();
  ASSERT_THAT(crypto_key_handle, NotNull());

  auto ec_key_method = EC_KEY_OpenSSL();
  ASSERT_THAT(ec_key_method, NotNull());

  auto evp_pkey_or = MakeKmsEcEvpPkey(std::move(public_key_pem_bio_or.value()),
                                      std::move(crypto_key_handle),
                                      ec_key_method);
  ASSERT_THAT(evp_pkey_or, IsOk());

  auto evp_pkey = std::move(evp_pkey_or.value());
  EXPECT_EQ(EVP_PKEY_id(evp_pkey.get()), EVP_PKEY_EC);
}

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkeyErrorsOnNullBio) {
  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();
  auto ec_key_method = EC_KEY_OpenSSL();

  EXPECT_THAT(MakeKmsEcEvpPkey({nullptr, BIO_free},
                               std::move(crypto_key_handle),
                               ec_key_method),
              Not(IsOk()));

  EXPECT_THAT(MakeKmsEcEvpPkey({nullptr, nullptr},
                               std::move(crypto_key_handle),
                               ec_key_method),
              Not(IsOk()));
}

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkeyErrorsOnNullCryptoKeyHandle) {
  auto public_key_pem_bio_or = MakeOpenSslBioFromString(
      kEcdsaPublicKey, sizeof(kEcdsaPublicKey));
  auto ec_key_method = EC_KEY_OpenSSL();

  ASSERT_THAT(MakeKmsEcEvpPkey(std::move(public_key_pem_bio_or.value()),
                               nullptr,
                               ec_key_method),
              Not(IsOk()));
}

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkeyErrorsOnNullRsaMethod) {
  auto public_key_pem_bio_or = MakeOpenSslBioFromString(
      kEcdsaPublicKey, sizeof(kEcdsaPublicKey));
  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();

  ASSERT_THAT(MakeKmsEcEvpPkey(std::move(public_key_pem_bio_or.value()),
                               std::move(crypto_key_handle),
                               nullptr),
              Not(IsOk()));
}

}  // namespace
}  // namespace key_loader
}  // namespace bridge
}  // namespace kmsengine
