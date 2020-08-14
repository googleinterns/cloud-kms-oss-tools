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

#include <cstring>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>

#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/bridge/memory_util/openssl_bio.h"
#include "src/bridge/crypto/rsa.h"
#include "src/testing_util/mock_crypto_key_handle.h"
#include "src/testing_util/openssl_assertions.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace crypto {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockCryptoKeyHandle;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::HasSubstr;

const std::string kSampleSignature = "my signature";

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

// Creates an `OpenSslRsa` from the PEM-encoded public key data loaded in
// `public_key_bio`. Returns an error `Status` if unsuccessful.
//
// The `RSA` struct contained within the returned `OpenSslRsa` will have its
// public key parameters set to the values from the input PEM.
StatusOr<OpenSslRsa> MakeRsaFromPublicKeyPemBio(OpenSslBio public_key_bio) {
  RSA *rsa = PEM_read_bio_RSA_PUBKEY(public_key_bio.get(), nullptr,
                                     nullptr, nullptr);
  if (rsa == nullptr) {
    return Status(StatusCode::kInternal, "PEM_read_bio_RSA_PUBKEY failed");
  }
  return OpenSslRsa(rsa, &RSA_free);
}

// Test fixture for calling initialization functions (normally called by the
// `EngineBind` function) needed for the RSA callbacks to work.
class RsaMethodTest : public ::testing::Test {
 protected:
  RsaMethodTest() : rsa_method_(nullptr, nullptr) {}

  void SetUp() override {
    StatusOr<OpenSslRsaMethod> kms_rsa_method_or = MakeKmsRsaMethod();
    ASSERT_THAT(kms_rsa_method_or, IsOk());
    rsa_method_ = std::move(kms_rsa_method_or.value());

    ASSERT_THAT(InitExternalIndices(), IsOk());
    ASSERT_THAT(rsa_method(), NotNull());
  }

  void TearDown() override {
    FreeExternalIndices();
  }

  // Convenience function for making an RSA struct with the Cloud KMS RSA_METHOD
  // implementation already attached.
  StatusOr<OpenSslRsa> MakeRsaWithKmsMethod() {
    KMSENGINE_ASSIGN_OR_RETURN(
        OpenSslBio pem_bio,
        MakeOpenSslMemoryBufferBio(kRsaPublicKey, sizeof(kRsaPublicKey)));
    KMSENGINE_ASSIGN_OR_RETURN(
        OpenSslRsa rsa, MakeRsaFromPublicKeyPemBio(std::move(pem_bio)));
    RSA_set_method(rsa.get(), rsa_method());
    return rsa;
  }

  RSA_METHOD *rsa_method() { return rsa_method_.get(); }

 private:
  OpenSslRsaMethod rsa_method_;
};

TEST_F(RsaMethodTest, RsaMethodCallbacksAreInitialized) {
  // The OpenSSL specification does not explicitly permit these RSA operations
  // to be null, so we check to make sure that they're defined.
  //
  // The other operations (`mod_exp`, `bn_mod_exp`, and `keygen`) may be null
  // according to the OpenSSL specification (but they may also be defined).
  EXPECT_THAT(RSA_meth_get_pub_enc(rsa_method()), NotNull());
  EXPECT_THAT(RSA_meth_get_pub_dec(rsa_method()), NotNull());
  EXPECT_THAT(RSA_meth_get_verify(rsa_method()), NotNull());
  EXPECT_THAT(RSA_meth_get_priv_dec(rsa_method()), NotNull());
  EXPECT_THAT(RSA_meth_get_priv_enc(rsa_method()), NotNull());
  EXPECT_THAT(RSA_meth_get_sign(rsa_method()), NotNull());
  EXPECT_THAT(RSA_meth_get_init(rsa_method()), NotNull());
  EXPECT_THAT(RSA_meth_get_finish(rsa_method()), NotNull());
}

TEST_F(RsaMethodTest, FinishCleansUpCryptoKeyHandle) {
  // Using `RSA_new` instead of `MakeRsa` here so we can explicitly call
  // `RSA_free` at the end to test that the mock got cleaned up.
  RSA *rsa = RSA_new();
  ASSERT_THAT(rsa, NotNull());
  RSA_set_method(rsa, rsa_method());

  // If mocks aren't deleted before the end of a test, an error is raised.
  // Thus, if `RSA_free` doesn't delete the underlying `CryptoKeyHandle`, then
  // this test will fail.
  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa), IsOk());

  RSA_free(rsa);
}

TEST_F(RsaMethodTest, SignReturnsSignature) {
  // Construct the RSA struct within the test body as opposed to the fixture
  // so it cleans itself up before the end of the test. This is important so
  // that it deletes the `MockCryptoKeyHandle` before the test body ends
  // (otherwise a testing error will be raised).
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());

  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  EXPECT_CALL(*handle, Sign).WillOnce(
      Return(StatusOr<std::string>(kSampleSignature)));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "my digest";
  unsigned char signature[kSampleSignature.length()];
  unsigned int signature_length;
  ASSERT_OPENSSL_SUCCESS(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), signature, &signature_length,
               rsa.get()));

  std::string actual(reinterpret_cast<char *>(signature), signature_length);
  EXPECT_THAT(actual, StrEq(kSampleSignature));
}

TEST_F(RsaMethodTest, SignHandlesNullSignaturePointer) {
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());

  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "my digest";
  unsigned int signature_length;
  ASSERT_OPENSSL_SUCCESS(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), nullptr, &signature_length, rsa.get()));

  EXPECT_EQ(signature_length, RSA_size(rsa.get()));
}

TEST_F(RsaMethodTest, SignHandlesNullSignatureLengthPointer) {
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());

  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "my digest";
  unsigned char signature[kSampleSignature.length()];
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), signature, nullptr, rsa.get()),
      HasSubstr("Signature length parameter may not be null"));
}

TEST_F(RsaMethodTest, SignHandlesNullSignatureAndNullLengthPointer) {
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());

  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "my digest";
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), nullptr, nullptr, rsa.get()),
      HasSubstr("Signature length parameter may not be null"));
}

TEST_F(RsaMethodTest, SignHandlesCryptoKeyHandleSignMethodErrors) {
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());

  auto expected_error_message = "mock CryptoKeyHandle::Sign failed";
  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  EXPECT_CALL(*handle, Sign).WillOnce(Return(StatusOr<std::string>(
      Status(StatusCode::kInternal, expected_error_message))));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "my digest";
  unsigned char signature[kSampleSignature.length()];
  unsigned int signature_length;
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), signature, &signature_length, rsa.get()),
      HasSubstr(expected_error_message));
}

TEST_F(RsaMethodTest, SignHandlesMissingCryptoKeyHandle) {
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa.get()), IsOk());

  std::string digest = "my digest";
  unsigned char signature[kSampleSignature.length()];
  unsigned int signature_length;
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), signature, &signature_length, rsa.get()),
      HasSubstr("RSA instance was not initialized with Cloud KMS data"));
}

TEST_F(RsaMethodTest, SignHandlesBadNidDigestTypes) {
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());

  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  EXPECT_CALL(*handle, Sign).Times(0);
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  // Use MD5 as our "bad digest type" example, since it's not supported by
  // Cloud KMS (and since it's an insecure algorithm, it probably won't be
  // supported in the future).
  constexpr auto kBadDigestType = NID_md5;
  std::string digest = "my digest";
  unsigned char signature[kSampleSignature.length()];
  unsigned int signature_length;
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(kBadDigestType, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), signature, &signature_length, rsa.get()),
      HasSubstr("Unsupported digest type"));
}

TEST_F(RsaMethodTest, SignHandlesSignatureLongerThanRsaSize) {
  StatusOr<OpenSslRsa> rsa_or = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa_or, IsOk());
  OpenSslRsa rsa = std::move(rsa_or.value());

  // Generate a signature that is 1 byte longer than `RSA_size(rsa)`, and have
  // mock return that signature to test that `RSA_sign` handles the case where
  // the signature returned by the API is unexpectedly longer than `RSA_size`.
  std::string kTooLongSignature("a", RSA_size(rsa.get()) + 1);
  MockCryptoKeyHandle *handle = new MockCryptoKeyHandle();
  EXPECT_CALL(*handle, Sign).WillOnce(
      Return(StatusOr<std::string>(kTooLongSignature)));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "my digest";
  unsigned char signature[kTooLongSignature.length()];
  unsigned int signature_length;
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), signature, &signature_length,
               rsa.get()),
      HasSubstr("Generated signature length was unexpectedly larger than "
                "RSA_size(rsa)"));
}

}  // namespace
}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine
