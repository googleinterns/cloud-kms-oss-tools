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

// Test fixture for calling initialization functions (normally called by the
// `EngineBind` function) needed for the RSA callbacks to work.
class RsaMethodTest : public ::testing::Test {
 protected:
  RsaMethodTest() : rsa_method_(MakeKmsRsaMethod()) {}

  void SetUp() override {
    ASSERT_THAT(InitExternalIndices(), IsOk());
    ASSERT_THAT(rsa_method(), NotNull());
  }

  void TearDown() override {
    FreeExternalIndices();
  }

  // Convenience function for making an RSA struct with the Cloud KMS RSA_METHOD
  // implementation already attached.
  OpenSslRsa MakeRsaWithKmsMethod() {
    auto rsa = MakeRsa();
    if (rsa) RSA_set_method(rsa.get(), rsa_method());
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
  auto handle = new MockCryptoKeyHandle();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa), IsOk());

  RSA_free(rsa);
}

TEST_F(RsaMethodTest, SignReturnsSignature) {
  // Construct the RSA struct within the test body as opposed to the fixture
  // so it cleans itself up before the end of the test. This is important so
  // that it deletes the `MockCryptoKeyHandle` before the test body ends
  // (otherwise a testing error will be raised).
  OpenSslRsa rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());

  std::string expected = "my signature";
  auto handle = new MockCryptoKeyHandle();
  EXPECT_CALL(*handle, Sign).WillOnce(Return(StatusOr<std::string>(expected)));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "sample digest";
  unsigned char signature[expected.length()];
  unsigned int signature_length;
  ASSERT_OPENSSL_SUCCESS(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), signature, &signature_length, rsa.get()));

  std::string actual(reinterpret_cast<char *>(signature), signature_length);
  EXPECT_THAT(actual, StrEq(expected));
}

TEST_F(RsaMethodTest, SignHandlesCryptoKeyHandleSignMethodErrors) {
  OpenSslRsa rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());

  auto expected_error_message = "mock CryptoKeyHandle::Sign failed";
  auto handle = new MockCryptoKeyHandle();
  EXPECT_CALL(*handle, Sign).WillOnce(Return(StatusOr<std::string>(
      Status(StatusCode::kInternal, expected_error_message))));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  std::string digest = "sample digest";
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), nullptr, nullptr, rsa.get()),
      HasSubstr(expected_error_message));
}

TEST_F(RsaMethodTest, SignHandlesMissingCryptoKeyHandle) {
  OpenSslRsa rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa.get()), IsOk());

  std::string digest = "sample digest";
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), nullptr, nullptr, rsa.get()),
      HasSubstr("RSA instance was not initialized with Cloud KMS data"));
}

TEST_F(RsaMethodTest, SignHandlesBadNidDigestTypes) {
  OpenSslRsa rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());

  auto handle = new MockCryptoKeyHandle();
  EXPECT_CALL(*handle, Sign).Times(0);
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(handle, rsa.get()), IsOk());

  // Use MD5 as our "bad digest type" example, since it's not supported by
  // Cloud KMS (and since it's an insecure algorithm, it probably won't be
  // supported in the future).
  constexpr auto kBadDigestType = NID_md5;
  std::string digest = "sample digest";
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(kBadDigestType, reinterpret_cast<unsigned char *>(&digest[0]),
               digest.length(), nullptr, nullptr, rsa.get()),
      HasSubstr("Unsupported digest type"));
}

}  // namespace
}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine
