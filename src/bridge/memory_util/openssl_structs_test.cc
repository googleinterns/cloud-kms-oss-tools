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
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::testing::NotNull;

TEST(OpenSslMakeTest, MakeEcKeySetsDeleter) {
  OpenSslEcKey ec_key = MakeEcKey();
  ASSERT_THAT(ec_key, NotNull());
  EXPECT_EQ(ec_key.get_deleter(), &EC_KEY_free);
}

TEST(OpenSslMakeTest, MakeEcKeyMethodSetsDeleter) {
  OpenSslEcKeyMethod ec_key_method = MakeEcKeyMethod();
  ASSERT_THAT(ec_key_method, NotNull());
  EXPECT_EQ(ec_key_method.get_deleter(), &EC_KEY_METHOD_free);
}

TEST(OpenSslMakeTest, MakeEcKeyMethodPerformsShallowCopy) {
  const EC_KEY_METHOD *default_ec_key_method = EC_KEY_OpenSSL();

  OpenSslEcKeyMethod ec_key_method = MakeEcKeyMethod(default_ec_key_method);
  ASSERT_THAT(ec_key_method, NotNull());
  EXPECT_EQ(ec_key_method.get_deleter(), &EC_KEY_METHOD_free);

  int (*actual_keygen_function)(EC_KEY *key) = nullptr;
  EC_KEY_METHOD_get_keygen(ec_key_method.get(), &actual_keygen_function);

  int (*expected_keygen_function)(EC_KEY *key) = nullptr;
  EC_KEY_METHOD_get_keygen(default_ec_key_method, &expected_keygen_function);

  EXPECT_EQ(actual_keygen_function, expected_keygen_function);
}

TEST(OpenSslMakeTest, MakeEngineSetsDeleter) {
  OpenSslEngine engine = MakeEngine();
  ASSERT_THAT(engine, NotNull());
  EXPECT_EQ(engine.get_deleter(), &ENGINE_free);
}

TEST(OpenSslMakeTest, MakeEvpPkeySetsDeleter) {
  OpenSslEvpPkey evp_pkey = MakeEvpPkey();
  ASSERT_THAT(evp_pkey, NotNull());
  EXPECT_EQ(evp_pkey.get_deleter(), &EVP_PKEY_free);
}

TEST(OpenSslMakeTest, MakeEvpDigestContextSetsDeleter) {
  OpenSslEvpDigestContext context = MakeEvpDigestContext();
  ASSERT_THAT(context, NotNull());
  EXPECT_EQ(context.get_deleter(), &EVP_MD_CTX_free);
}

TEST(OpenSslStructsTest, MakeRsaSetsDeleter) {
  OpenSslRsa rsa = MakeRsa();
  ASSERT_THAT(rsa, NotNull());
  EXPECT_EQ(rsa.get_deleter(), &RSA_free);
}

TEST(OpenSslStructsTest, MakeRsaMethodSetsDeleter) {
  OpenSslRsaMethod rsa_method = MakeRsaMethod("", 0);
  ASSERT_THAT(rsa_method, NotNull());
  EXPECT_EQ(rsa_method.get_deleter(), &RSA_meth_free);
}

TEST(OpenSslStructsTest, MakeRsaMethodSetsName) {
  OpenSslRsaMethod empty_name = MakeRsaMethod("", 0);
  ASSERT_THAT(empty_name, NotNull());
  EXPECT_STREQ(RSA_meth_get0_name(empty_name.get()), "");

  OpenSslRsaMethod some_name = MakeRsaMethod("my-name", 0);
  ASSERT_THAT(some_name, NotNull());
  EXPECT_STREQ(RSA_meth_get0_name(some_name.get()), "my-name");
}

TEST(OpenSslStructsTest, MakeRsaMethodSetsFlags) {
  OpenSslRsaMethod with_flag = MakeRsaMethod("", RSA_FLAG_EXT_PKEY);
  ASSERT_THAT(with_flag, NotNull());
  EXPECT_TRUE(RSA_meth_get_flags(with_flag.get()) & RSA_FLAG_EXT_PKEY);

  OpenSslRsaMethod without_flag = MakeRsaMethod("", 0);
  ASSERT_THAT(without_flag, NotNull());
  EXPECT_FALSE(RSA_meth_get_flags(without_flag.get()) & RSA_FLAG_EXT_PKEY);
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
