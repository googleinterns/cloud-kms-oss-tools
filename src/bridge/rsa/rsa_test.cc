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

namespace kmsengine {
namespace bridge {
namespace rsa {
namespace {

using ::testing::Return;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::Matches;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockRsaKey;

testing::AssertionResult IsOpenSslSuccess(const char* expr,
                                          bool openssl_return) {
  if (openssl_return) return testing::AssertionSuccess();

  const char *file, *data;
  int line, flags;
  auto err = ERR_get_error_line_data(&file, &line, &data, &flags);
  if (err) {
    return testing::AssertionFailure()
           << expr << " unexpectedly returned false and produced OpenSSL "
           << "error...\n"
           << "         Expected: success\n"
           << "           Actual: error in " << file << ":" << line << "\n"
           << "                   [" << data << "]";
  } else {
    return testing::AssertionFailure()
           << expr << " unexpectedly returned false"
           << "         Expected: success\n"
           << "           Actual: failure (no OpenSSL error)";
  }
}

testing::AssertionResult IsOpenSslFailure(const char* return_expr,
                                          const char* status_expr,
                                          bool openssl_return,
                                          const char* substr_error) {
  if (openssl_return) {
    return testing::AssertionFailure()
           << return_expr << " should have returned false, but returned "
           << "true...\n"
           << "         Expected: failure with OpenSSL error\n"
           << "           Actual: success";
  }

  const char *file, *data;
  int line, flags;
  auto err = ERR_get_error_line_data(&file, &line, &data, &flags);
  if (!err) {
    return testing::AssertionFailure()
           << return_expr << " returned false, but no OpenSSL "
           << "         Expected: failure with OpenSSL error\n"
           << "           Actual: failure, but no OpenSSL error";
  }

  if (Matches(HasSubstr(substr_error))(data)) {
    return testing::AssertionSuccess();
  } else {
      return testing::AssertionFailure()
         << return_expr << " returned false and produced OpenSSL error, but "
         << "OpenSSL error did not contain expected substring...\n"
         << "         Expected: error containing '" << substr_error << "'\n"
         << "           Actual: error in " << file << ":" << line << "\n"
         << "                   [" << data << "]";
  }
}

#define ASSERT_OPENSSL_SUCCESS(val) \
  ASSERT_PRED_FORMAT1(IsOpenSslSuccess, val)

#define ASSERT_OPENSSL_FAILURE(val, status) \
  ASSERT_PRED_FORMAT2(IsOpenSslFailure, val, status)

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

TEST_F(RsaTest, SignWorks) {
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

}  // namespace
}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
