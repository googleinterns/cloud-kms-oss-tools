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

#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/testing_util/mock_client.h"
#include "src/testing_util/mock_rsa_key.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockClient;
using ::kmsengine::testing_util::MockRsaKey;
using ::testing::AtLeast;
using ::testing::Not;
using ::testing::Return;

TEST(ExDataUtilTest, InitSuccess) {
  auto status = InitExternalIndicies();
  EXPECT_THAT(status, IsOk());

  // Just check that FreeExternalIndicies is callable.
  (void)FreeExternalIndicies();
}

TEST(ExDataUtilTest, RsaKeyRoundtrip) {
  auto status = InitExternalIndicies();
  ASSERT_THAT(status, IsOk());

  auto rsa = MakeRsa();
  MockRsaKey rsa_key;

  EXPECT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), IsOk());
  EXPECT_EQ(GetRsaKeyFromOpenSslRsa(rsa.get()), &rsa_key);
}

TEST(ExDataUtilTest, ClientRoundtrip) {
  auto status = InitExternalIndicies();
  ASSERT_THAT(status, IsOk());

  auto engine = MakeEngine();
  MockClient client;

  EXPECT_THAT(AttachClientToOpenSslEngine(&client, engine.get()), IsOk());
  EXPECT_EQ(GetClientFromOpenSslEngine(engine.get()), &client);
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
