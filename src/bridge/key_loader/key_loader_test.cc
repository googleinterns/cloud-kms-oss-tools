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
#include "absl/strings/str_format.h"
#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/key_loader/key_loader.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/testing_util/mock_client.h"
#include "src/testing_util/openssl_assertions.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::backing::CryptoKeyHandle;
using ::kmsengine::backing::CryptoKeyVersionAlgorithm;
using ::kmsengine::backing::PublicKey;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockClient;
using ::testing::AtLeast;
using ::testing::Combine;
using ::testing::HasSubstr;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::ValuesIn;

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

// List of `CryptoKeyVersionAlgorithm`s that are currently unsupported by the
// engine.
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
      "bababa"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "ababab"),
  // Ends with null bytes.
  absl::HexStringToBytes(
      "bababa"
      "0000000000000000000000000000000000000000000000000000000000000000000000"),
  // Starts with null bytes and ends with non-null bytes.
  absl::HexStringToBytes(
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "ababab"),
  // Check all null string.
  absl::HexStringToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000000000"),
  // Check some arbitrary short string.
  "my unique signature",
  // Check empty string.
  "",
};

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

// A random 2048-bit / 256-byte ECDSA public key, encoded in PEM format.
constexpr char kEcdsaPublicKey[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xOUetsCa8EfOlDEBAfREhJqspDo\n"
  "yEh6Szz2in47Tv5n52m9dLYyPCbqZkOB5nTSqtscpkQD/HpykCggvx09iQ==\n"
  "-----END PUBLIC KEY-----\n";

// Byte size of the RSA key represented by `kRsaPublicKey`. Used to check that
// our engine initializes the public key size parameters correctly when
// asked to load `kRsaPublicKey`.
constexpr int kExpectedKeySize = 256;

TEST(KeyLoaderTest, HandlesBadEngineData) {
  EXPECT_THAT(InitExternalIndices(), IsOk());

  // Should fail since no `EngineData` is attached to `ENGINE`.
  auto engine = MakeEngine();
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()), IsOk());
  EXPECT_OPENSSL_FAILURE(
      LoadPrivateKey(engine.get(), "resource_id", nullptr, nullptr),
      HasSubstr("ENGINE instance was not initialized with Cloud KMS data"));

  FreeExternalIndices();
}

// Fixture for testing `LoadPrivateKey`. The fixture initializes (and cleans
// up) the `ex_data_util` system, which is necessary since `LoadPrivateKey`
// invokes `ex_data_util` functions. (This initialization is normally done by
// the engine when it is initialized in `EngineBind`.) The fixture also
// instantiates a new `ENGINE` struct.
class KeyLoaderTest : public ::testing::TestWithParam<
    std::tuple<CryptoKeyVersionAlgorithm, std::string>> {
 protected:
  KeyLoaderTest() : engine_(MakeEngine()) {}

  void SetUp() override {
    ASSERT_THAT(InitExternalIndices(), IsOk());
    ASSERT_THAT(engine(), NotNull());
  }

  void TearDown() override {
    FreeExternalIndices();
  }

  // Returns a pointer to the `ENGINE` to use in the test case.
  ENGINE *engine() { return engine_.get(); }

 private:
  const OpenSslEngine engine_;
};

// Fixture that sets up useful mocks and test variables in preparation for a
// `LoadPrivateKey` test with an RSA key.
class RsaKeyLoaderTest : public KeyLoaderTest {
 protected:
  RsaKeyLoaderTest()
      : expected_signature_(std::get<1>(GetParam())),
        public_key_(PublicKey(kRsaPublicKey, std::get<0>(GetParam()))),
        engine_data_(absl::make_unique<MockClient>(),
                     // `RSA_PKCS1_OpenSSL` returns the default OpenSSL
                     // `RSA_METHOD`. We use a no-op deleter here since
                     // `RSA_meth_free` does not support the pointer returned
                     // by `RSA_PKCS1_OpenSSL`.
                     OpenSslRsaMethod(
                        const_cast<RSA_METHOD *>(RSA_PKCS1_OpenSSL()),
                        [](RSA_METHOD *method) {}),
                     // `EC_KEY_OpenSSL` returns the default OpenSSL
                     // `EC_KEY_METHOD`.
                     OpenSslEcKeyMethod(
                        const_cast<EC_KEY_METHOD *>(EC_KEY_OpenSSL()),
                        EC_KEY_METHOD_free)) {}

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

  // Returns a pointer to the parameterized string to use as the signature in
  // the test case.
  std::string const& expected_signature() { return expected_signature_; }

  // Returns a fake public key to use in the test case.
  PublicKey const& public_key() { return public_key_; }

  // Returns a pointer to the `EngineData` to use in the test case.
  EngineData const& engine_data() { return engine_data_; }

  // Returns a reference to the `MockClient` attached to `engine_data()` so the
  // test can set custom expectations on the mock.
  MockClient const& mock_client() {
    return static_cast<MockClient const&>(engine_data().client());
  }

 private:
  const std::string expected_signature_;
  const PublicKey public_key_;
  const EngineData engine_data_;
};

INSTANTIATE_TEST_SUITE_P(
    RsaAlgorithmParameters, RsaKeyLoaderTest,
    Combine(ValuesIn(kRsaSignAlgorithms), ValuesIn(kSampleSignatures)));

TEST_P(RsaKeyLoaderTest, GeneratedKeyContainsHasTypeRsa) {
  EXPECT_CALL(mock_client(), GetPublicKey);

  EVP_PKEY *evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr,
                                      nullptr);
  ASSERT_THAT(evp_pkey, NotNull());

  EXPECT_EQ(EVP_PKEY_size(evp_pkey), kExpectedKeySize);
  EXPECT_EQ(EVP_PKEY_id(evp_pkey), EVP_PKEY_RSA)
      << "Object ID of EVP_PKEY should be EVP_PKEY_RSA";
  EXPECT_THAT(EVP_PKEY_get0_RSA(evp_pkey), NotNull());

  EVP_PKEY_free(evp_pkey);
}

TEST_P(RsaKeyLoaderTest, AttachedRsaStructHasCryptoKeyHandleWithCorrectKeyId) {
  EXPECT_CALL(mock_client(), GetPublicKey);

  EVP_PKEY *evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr,
                                      nullptr);
  ASSERT_THAT(evp_pkey, NotNull());

  auto handle = GetCryptoKeyHandleFromOpenSslRsa(EVP_PKEY_get0_RSA(evp_pkey));
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT(handle.value()->key_resource_id(), StrEq(kKeyResourceId))
      << "RsaKey should contain the key resource ID loaded in LoadPrivateKey";

  EVP_PKEY_free(evp_pkey);
}

TEST_P(RsaKeyLoaderTest, AttachedRsaStructHasCorrectRsaMethodImplementation) {
  EXPECT_CALL(mock_client(), GetPublicKey);

  EVP_PKEY *evp_pkey = LoadPrivateKey(engine(), kKeyResourceId, nullptr,
                                      nullptr);
  ASSERT_THAT(evp_pkey, NotNull());

  EXPECT_EQ(RSA_get_method(EVP_PKEY_get0_RSA(evp_pkey)),
            engine_data().rsa_method())
      << "Underlying RSA struct of EVP_PKEY should be initialized with the "
         "EngineData's RSA_METHOD";

  EVP_PKEY_free(evp_pkey);
}

// TODO(https://github.com/googleinterns/cloud-kms-oss-tools/pull/114): Add
// more integrated RSA_METHOD tests once RSA_METHOD implementation is in.

// Fixture that sets up useful mocks and test variables in preparation for a
// `LoadPrivateKey` test with an ECDSA key.
class EcKeyLoaderTest : public KeyLoaderTest {
 protected:
  EcKeyLoaderTest()
      : public_key_(PublicKey(kRsaPublicKey, std::get<0>(GetParam()))) {}

  // Returns a fake public key to use in the test case.
  PublicKey public_key() { return public_key_; }

 private:
  const PublicKey public_key_;
};

INSTANTIATE_TEST_SUITE_P(
    EcAlgorithmParameters, EcKeyLoaderTest,
    Combine(ValuesIn(kEcSignAlgorithms), ValuesIn(kSampleSignatures)));

// TODO(https://github.com/googleinterns/cloud-kms-oss-tools/pull/113): Add
// EC_KEY loader tests in
// https://github.com/googleinterns/cloud-kms-oss-tools/pull/113.

// Fixture that sets up useful mocks and test variables in preparation for a
// `LoadPrivateKey` test with a key of a particular `CryptoKeyVersionAlgorithm`
// type that corresponds to an unsupported sign operation.
class UnsupportedKeyLoaderTest : public KeyLoaderTest {};

INSTANTIATE_TEST_SUITE_P(
    UnsupportedAlgorithmParameters, UnsupportedKeyLoaderTest,
    Combine(ValuesIn(kUnsupportedAlgorithms), ValuesIn(kSampleSignatures)));

TEST_P(UnsupportedKeyLoaderTest, LoadPrivateKey) {
  const CryptoKeyVersionAlgorithm algorithm = std::get<0>(GetParam());

  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey).WillOnce(Return(PublicKey("", algorithm)));

  auto engine_data = absl::make_unique<EngineData>(
      std::move(client),
      OpenSslRsaMethod(nullptr, nullptr),
      OpenSslEcKeyMethod(nullptr, nullptr));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(engine_data.get(), engine()),
              IsOk());

  EXPECT_OPENSSL_FAILURE(
      LoadPrivateKey(engine(), kKeyResourceId, nullptr, nullptr),
      HasSubstr(
          absl::StrFormat("Cloud KMS key had unsupported type %s",
                          CryptoKeyVersionAlgorithmToString(algorithm))));
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
