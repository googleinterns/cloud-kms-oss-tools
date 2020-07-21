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
#include "src/bridge/rsa/rsa.h"
#include "src/testing_util/mock_rsa_key.h"
#include "src/testing_util/openssl_assertions.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace rsa {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockRsaKey;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::StrEq;

// Test fixture for calling initialization functions (normally called by the
// `EngineBind` function) needed for the RSA callbacks to work.
class RsaMethodTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(InitExternalIndicies(), IsOk());
    ASSERT_THAT(rsa_method, NotNull());
  }

  void TearDown() override {
    FreeExternalIndicies();
  }

  // Convenience function for making an RSA struct with the Cloud KMS RSA_METHOD
  // implementation already attached.
  OpenSslRsa MakeRsaWithKmsMethod() {
    auto rsa = MakeRsa();
    if (rsa) RSA_set_method(rsa.get(), rsa_method.get());
    return rsa;
  }

  OpenSslRsaMethod rsa_method {MakeKmsRsaMethod()};
};

TEST_F(RsaMethodTest, FinishCleansUpRsaKey) {
  // Using `RSA_new` instead of `MakeRsa` here so we can explicitly call
  // `RSA_free` at the end to test that the mock got cleaned up.
  auto rsa = RSA_new();
  ASSERT_THAT(rsa, NotNull());
  RSA_set_method(rsa, rsa_method.get());

  // If mocks aren't deleted before the end of a test, an error is raised.
  // Thus, if `RSA_free` doesn't delete the underlying `RsaKey`, then this test
  // will fail.
  auto rsa_key = new MockRsaKey();
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(rsa_key, rsa), IsOk());

  RSA_free(rsa);
}

TEST_F(RsaMethodTest, SignReturnsSignature) {
  // Construct the RSA struct within the test body as opposed to the fixture
  // so it cleans itself up before the end of the test. This is important so
  // that it deletes the `MockRsaKey` before the test body ends (otherwise a
  // testing error will be raised).
  auto rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());

  std::string expected = "my signature";
  auto rsa_key = new MockRsaKey();
  EXPECT_CALL(*rsa_key, Sign).WillOnce(Return(StatusOr<std::string>(expected)));
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(rsa_key, rsa.get()), IsOk());

  unsigned char msg[] = "sample digest";
  unsigned int msg_length = std::strlen(reinterpret_cast<char *>(msg));
  unsigned char signature[expected.length()];
  unsigned int signature_length;
  ASSERT_OPENSSL_SUCCESS(RSA_sign(NID_sha256, msg, msg_length, signature,
                                  &signature_length, rsa.get()));

  std::string actual(reinterpret_cast<char *>(signature), signature_length);
  EXPECT_THAT(actual, StrEq(expected));
}

TEST_F(RsaMethodTest, SignHandlesRsaKeySignMethodErrors) {
  auto rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());

  auto expected_error_message = "mock RsaKey::Sign failed";
  auto rsa_key = new MockRsaKey();
  EXPECT_CALL(*rsa_key, Sign).WillOnce(Return(StatusOr<std::string>(
      Status(StatusCode::kInternal, expected_error_message))));
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(rsa_key, rsa.get()), IsOk());

  unsigned char msg[] = "sample digest";
  unsigned int msg_length = std::strlen(reinterpret_cast<char *>(msg));
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, msg, msg_length, nullptr, nullptr, rsa.get()),
      expected_error_message);
}

TEST_F(RsaMethodTest, SignHandlesMissingRsaKeys) {
  auto rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(nullptr, rsa.get()), IsOk());

  unsigned char msg[] = "sample digest";
  unsigned int msg_length = std::strlen(reinterpret_cast<char *>(msg));
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_sha256, msg, msg_length, nullptr, nullptr, rsa.get()),
      "No Cloud KMS key associated with RSA struct");
}

TEST_F(RsaMethodTest, SignHandlesBadNidDigestTypes) {
  auto rsa = MakeRsaWithKmsMethod();
  ASSERT_THAT(rsa, NotNull());

  auto rsa_key = new MockRsaKey();
  EXPECT_CALL(*rsa_key, Sign).Times(0);
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(rsa_key, rsa.get()), IsOk());

  // Use MD5 as our "bad digest type" example, since it's not supported by
  // Cloud KMS (and since it's an insecure algorithm, it probably won't be
  // supported in the future).
  unsigned char msg[] = "sample digest";
  unsigned int msg_length = std::strlen(reinterpret_cast<char *>(msg));
  EXPECT_OPENSSL_FAILURE(
      RSA_sign(NID_md5, msg, msg_length, nullptr, nullptr, rsa.get()),
      "Unsupported digest type");
}

}  // namespace
}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
