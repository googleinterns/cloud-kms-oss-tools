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

// `EC_KEY_OpenSSL` is OpenSSL's default `EC_KEY_METHOD` implementation.
const EC_KEY_METHOD *kDefaultOpenSslEcKeyMethod = EC_KEY_OpenSSL();

// Fixture for testing `MakeKmsEcEvpPkey`. The fixture initializes (and cleans
// up) the `ex_data_util` system, which is necessary since `MakeKmsEcEvpPkey`
// invokes `ex_data_util` functions. (This initialization is normally done by
// the engine when it is initialized in `EngineBind`.)
class EcKeyLoaderTest : public ::testing::Test {
  void SetUp() override {
    ASSERT_THAT(InitExternalIndicies(), IsOk());
  }

  void TearDown() override {
    FreeExternalIndicies();
  }
};

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkey) {
  StatusOr<OpenSslBio> public_key_pem_bio_or =
      MakeOpenSslMemoryBufferBio(kEcdsaPublicKey, sizeof(kEcdsaPublicKey));
  ASSERT_THAT(public_key_pem_bio_or, IsOk());

  StatusOr<OpenSslEvpPkey> evp_pkey_or =
      MakeKmsEcEvpPkey(std::move(public_key_pem_bio_or.value()),
                       absl::make_unique<MockCryptoKeyHandle>(),
                       kDefaultOpenSslEcKeyMethod);
  ASSERT_THAT(evp_pkey_or, IsOk());

  EXPECT_EQ(EVP_PKEY_id(evp_pkey_or.value().get()), EVP_PKEY_EC);
}

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkeyErrorsOnNullBioWithDeleter) {
  EXPECT_THAT(MakeKmsEcEvpPkey(OpenSslBio(nullptr, BIO_free),
                               absl::make_unique<MockCryptoKeyHandle>(),
                               kDefaultOpenSslEcKeyMethod),
              Not(IsOk()));
}

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkeyErrorsOnNullBioWithoutDeleter) {
  EXPECT_THAT(MakeKmsEcEvpPkey(OpenSslBio(nullptr, nullptr),
                               absl::make_unique<MockCryptoKeyHandle>(),
                               kDefaultOpenSslEcKeyMethod),
              Not(IsOk()));
}

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkeyErrorsOnNullCryptoKeyHandle) {
  StatusOr<OpenSslBio> public_key_pem_bio_or =
      MakeOpenSslMemoryBufferBio(kEcdsaPublicKey, sizeof(kEcdsaPublicKey));

  EXPECT_THAT(MakeKmsEcEvpPkey(std::move(public_key_pem_bio_or.value()),
                               nullptr,
                               kDefaultOpenSslEcKeyMethod),
              Not(IsOk()));
}

TEST_F(EcKeyLoaderTest, MakeKmsEcEvpPkeyErrorsOnNullRsaMethod) {
  StatusOr<OpenSslBio> public_key_pem_bio_or =
      MakeOpenSslMemoryBufferBio(kEcdsaPublicKey, sizeof(kEcdsaPublicKey));

  EXPECT_THAT(MakeKmsEcEvpPkey(std::move(public_key_pem_bio_or.value()),
                               absl::make_unique<MockCryptoKeyHandle>(),
                               nullptr),
              Not(IsOk()));
}

}  // namespace
}  // namespace key_loader
}  // namespace bridge
}  // namespace kmsengine
