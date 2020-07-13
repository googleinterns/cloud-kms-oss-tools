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
#include <openssl/engine.h>
#include <openssl/rsa.h>

#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::testing::Not;
using ::testing::IsNull;

TEST(OpenSSLMakeTest, MakeENGINESetsDeleter) {
  auto engine = MakeEngine();
  ASSERT_THAT(engine, Not(IsNull()));
  EXPECT_EQ(engine.get_deleter(), &ENGINE_free);
}

TEST(OpenSSLMakeTest, MakeRsaSetsDeleter) {
  auto rsa = MakeRsa();
  ASSERT_THAT(rsa, Not(IsNull()));
  EXPECT_EQ(rsa.get_deleter(), &RSA_free);
}

TEST(OpenSSLMakeTest, MakeRsaMethodSetsDeleter) {
  auto rsa_method = MakeRsaMethod("", 0);
  ASSERT_THAT(rsa_method, Not(IsNull()));
  EXPECT_EQ(rsa_method.get_deleter(), &RSA_meth_free);
}

TEST(OpenSSLMakeTest, MakeRsaMethodSetsName) {
  auto empty_name = MakeRsaMethod("", 0);
  ASSERT_THAT(empty_name, Not(IsNull()));
  EXPECT_STREQ(RSA_meth_get0_name(empty_name.get()), "");

  auto some_name = MakeRsaMethod("my-name", 0);
  ASSERT_THAT(some_name, Not(IsNull()));
  EXPECT_STREQ(RSA_meth_get0_name(some_name.get()), "my-name");
}

TEST(OpenSSLMakeTest, MakeRsaMethodSetsFlags) {
  auto with_flag = MakeRsaMethod("", RSA_FLAG_EXT_PKEY);
  ASSERT_THAT(with_flag, Not(IsNull()));
  EXPECT_TRUE(RSA_meth_get_flags(with_flag.get()) & RSA_FLAG_EXT_PKEY);

  auto without_flag = MakeRsaMethod("", 0);
  ASSERT_THAT(without_flag, Not(IsNull()));
  EXPECT_FALSE(RSA_meth_get_flags(without_flag.get()) & RSA_FLAG_EXT_PKEY);
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
