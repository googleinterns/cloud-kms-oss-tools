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

#include "absl/memory/memory.h"
#include "src/bridge/memory_util/openssl_bio.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/key_loader/rsa_key_loader.h"
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

// A random 2048-bit / 256-byte RSA public key, encoded in PEM format.
constexpr char kRsaPublicKey[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
  "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"
  "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"
  "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"
  "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"
  "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"
  "wQIDAQAB\n"
  "-----END PUBLIC KEY-----\n";

// Fixture for testing `MakeKmsRsaEvpPkey`. The fixture initializes (and cleans
// up) the `ex_data_util` system, which is necessary since `MakeKmsRsaEvpPkey`
// invokes `ex_data_util` functions. (This initialization is normally done by
// the engine when it is initialized in `EngineBind`.)
class RsaKeyLoaderTest : public ::testing::Test {
  void SetUp() override {
    ASSERT_THAT(InitExternalIndicies(), IsOk());
  }

  void TearDown() override {
    FreeExternalIndicies();
  }
};

TEST_F(RsaKeyLoaderTest, MakeKmsRsaEvpPkey) {
  auto public_key_pem_bio_or = MakeOpenSslMemoryBufferBio(
      kRsaPublicKey, sizeof(kRsaPublicKey));
  ASSERT_THAT(public_key_pem_bio_or, IsOk());

  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();
  ASSERT_THAT(crypto_key_handle, NotNull());

  // `RSA_PKCS1_OpenSSL` returns the default OpenSSL `RSA_METHOD`.
  auto rsa_method = RSA_PKCS1_OpenSSL();
  ASSERT_THAT(rsa_method, NotNull());

  auto evp_pkey_or = MakeKmsRsaEvpPkey(std::move(public_key_pem_bio_or.value()),
                                       std::move(crypto_key_handle),
                                       rsa_method);
  ASSERT_THAT(evp_pkey_or, IsOk());

  auto evp_pkey = std::move(evp_pkey_or.value());
  EXPECT_EQ(EVP_PKEY_id(evp_pkey.get()), EVP_PKEY_RSA);
}

TEST_F(RsaKeyLoaderTest, MakeKmsRsaEvpPkeyErrorsOnNullBioWithDeleter) {
  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();
  auto rsa_method = RSA_PKCS1_OpenSSL();

  EXPECT_THAT(MakeKmsRsaEvpPkey({nullptr, BIO_free},
                                std::move(crypto_key_handle),
                                rsa_method),
              Not(IsOk()));
}

TEST_F(RsaKeyLoaderTest, MakeKmsRsaEvpPkeyErrorsOnNullBioWithoutDeleter) {
  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();
  auto rsa_method = RSA_PKCS1_OpenSSL();

  EXPECT_THAT(MakeKmsRsaEvpPkey({nullptr, nullptr},
                                std::move(crypto_key_handle),
                                rsa_method),
              Not(IsOk()));
}

TEST_F(RsaKeyLoaderTest, MakeKmsRsaEvpPkeyErrorsOnNullCryptoKeyHandle) {
  auto public_key_pem_bio_or = MakeOpenSslMemoryBufferBio(
      kRsaPublicKey, sizeof(kRsaPublicKey));
  auto rsa_method = RSA_PKCS1_OpenSSL();

  EXPECT_THAT(MakeKmsRsaEvpPkey(std::move(public_key_pem_bio_or.value()),
                                nullptr,
                                rsa_method),
              Not(IsOk()));
}

TEST_F(RsaKeyLoaderTest, MakeKmsRsaEvpPkeyErrorsOnNullRsaMethod) {
  auto public_key_pem_bio_or = MakeOpenSslMemoryBufferBio(
      kRsaPublicKey, sizeof(kRsaPublicKey));
  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();

  EXPECT_THAT(MakeKmsRsaEvpPkey(std::move(public_key_pem_bio_or.value()),
                                std::move(crypto_key_handle),
                                nullptr),
              Not(IsOk()));
}

}  // namespace
}  // namespace key_loader
}  // namespace bridge
}  // namespace kmsengine
