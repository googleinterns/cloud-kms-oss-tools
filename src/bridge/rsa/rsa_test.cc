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

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/bridge/rsa/rsa.h"
#include "src/testing_util/mock_rsa_key.h"
#include "src/testing_util/test_matchers.h"
#include "src/testing_util/openssl_assertions.h"

namespace kmsengine {
namespace bridge {
namespace rsa {
namespace {

using ::testing::Return;
using ::testing::StrEq;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockRsaKey;

// Test fixture for calling initialization functions (normally called by the
// `EngineBind` function) needed for the RSA callbacks to work.
class RsaTest : public ::testing::Test {
  void SetUp() override {
    ASSERT_THAT(InitExternalIndicies(), IsOk());
  }

  void TearDown() override {
    FreeExternalIndicies();
  }
};

TEST_F(RsaTest, SignReturnsSignature) {
  std::string expected = "my signature";

  MockRsaKey rsa_key;
  EXPECT_CALL(rsa_key, Sign).WillOnce(Return(StatusOr<std::string>(expected)));

  auto rsa = MakeRsa();
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), IsOk());

  unsigned char digest[] = "sample digest";
  unsigned int digest_length = std::strlen(reinterpret_cast<char *>(digest));
  unsigned char signature[expected.length()];
  unsigned int signature_length;
  ASSERT_OPENSSL_SUCCESS(Sign(NID_sha256, digest, digest_length, signature,
                              &signature_length, rsa.get()));

  std::string actual(reinterpret_cast<char *>(signature), signature_length);
  EXPECT_THAT(actual, StrEq(expected));
}

TEST_F(RsaTest, SignPropogatesErrors) {
  std::string expected_error = "mock RsaKey::Sign failed";

  MockRsaKey rsa_key;
  EXPECT_CALL(rsa_key, Sign).WillOnce(Return(StatusOr<std::string>(
      Status(StatusCode::kInternal, expected_error))));

  auto rsa = MakeRsa();
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), IsOk());

  unsigned char digest[] = "sample digest";
  unsigned int digest_length = std::strlen(reinterpret_cast<char *>(digest));
  unsigned char *signature;
  unsigned int signature_length;
  EXPECT_OPENSSL_FAILURE(Sign(NID_sha256, digest, digest_length, signature,
                              &signature_length, rsa.get()),
                         expected_error);
}

TEST_F(RsaTest, SignHandlesMissingRsaKeys) {
  std::string expected_error = "mock RsaKey::Sign failed";

  auto rsa = MakeRsa();
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(nullptr, rsa.get()), IsOk());

  unsigned char digest[] = "sample digest";
  unsigned int digest_length = std::strlen(reinterpret_cast<char *>(digest));
  unsigned char *signature;
  unsigned int signature_length;
  EXPECT_OPENSSL_FAILURE(Sign(NID_sha256, digest, digest_length, signature,
                              &signature_length, rsa.get()),
                         "No Cloud KMS key associated with RSA struct");
}

}  // namespace
}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
