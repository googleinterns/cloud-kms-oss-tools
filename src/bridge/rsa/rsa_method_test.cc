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

#include "src/bridge/memory_util/openssl_structs.h"
#include "src/bridge/rsa/rsa.h"
#include "src/bridge/rsa/rsa_method.h"
#include "src/testing_util/mock_rsa_key.h"

namespace kmsengine {
namespace bridge {
namespace rsa {
namespace {

using ::testing::Return;
using ::kmsengine::testing_util::MockRsaKey;

TEST(RsaMethodTest, ImplementationsAreAssigned) {
  auto rsa_method = MakeKmsRsaMethod();

  EXPECT_EQ(RSA_meth_get_pub_enc(rsa_method.get()), PublicEncrypt);
  EXPECT_EQ(RSA_meth_get_pub_dec(rsa_method.get()), PublicDecrypt);
  EXPECT_EQ(RSA_meth_get_priv_enc(rsa_method.get()), PrivateEncrypt);
  EXPECT_EQ(RSA_meth_get_priv_dec(rsa_method.get()), PrivateDecrypt);
  EXPECT_EQ(RSA_meth_get_sign(rsa_method.get()), Sign);
  EXPECT_EQ(RSA_meth_get_verify(rsa_method.get()), Verify);
  EXPECT_EQ(RSA_meth_get_mod_exp(rsa_method.get()), nullptr);
  EXPECT_EQ(RSA_meth_get_bn_mod_exp(rsa_method.get()), nullptr);
  EXPECT_EQ(RSA_meth_get_keygen(rsa_method.get()), nullptr);
  EXPECT_EQ(RSA_meth_get_init(rsa_method.get()), nullptr);
  EXPECT_EQ(RSA_meth_get_finish(rsa_method.get()), Finish);
}

TEST(RsaMethodTest, SignWorks) {
  // To make calls with the OpenSSL `RSA_*` functions, we need to generate an
  // `RSA` struct and attach our `RSA_METHOD` implementation to it.
  auto rsa = MakeRsa();
  auto rsa_method = MakeKmsRsaMethod();
  ASSERT_TRUE(RSA_set_method(rsa.get(), rsa_method.get()));

  int type = NID_sha256;
  const unsigned int digest_len = 36;
  const unsigned char digest[digest_len] = "testdigest";
  unsigned char actual[RSA_size(rsa.get())];
  unsigned int actual_length;
  ASSERT_TRUE(RSA_sign(NID_sha256, digest, digest_len, actual, &actual_length,
                       rsa.get()));


  // auto expected = "my signature";

  // MockRsaKey rsa_key;
  // EXPECT_CALL(rsa_key, PublicEncrypt).WillOnce(Return(StatusOr(expected)));

  // std::string fake_digest = "digest";


  // EXPECT_EQ(Sign())

  // EXPECT_EQ(RSA_sign(NID_sha256, static_cast<unsigned char*>(fake_digest),
  //                    fake_digest.length(), actual, &actual_length, rsa),
  //           OpenSSLReturn::kSuccess);
  // EXPECT_STREQ(actual, expected);
  // EXPECT_STREQ(actual_length, expected.length());
}

}  // namespace
}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
