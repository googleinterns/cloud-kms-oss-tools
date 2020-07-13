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
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockRsaKey;

TEST(RsaTest, SignWorks) {
  auto expected = "my signature";

  MockRsaKey rsa_key;
  EXPECT_CALL(rsa_key, PublicEncrypt)
      .WillOnce(Return(StatusOr<std::string>(expected)));

  unsigned char digest[] = "digest";
  int digest_len = 6;
  auto rsa = MakeRsa();
  EXPECT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), IsOk());

  unsigned char signature[RSA_size(rsa.get())];
  unsigned int signature_length;
  EXPECT_EQ(Sign(NID_sha256, digest, digest_len, signature, &signature_length,
            rsa.get()), 1);

  std::string actual(reinterpret_cast<char *>(signature), signature_length);
  EXPECT_THAT(actual, StrEq(expected));
}

}  // namespace
}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
