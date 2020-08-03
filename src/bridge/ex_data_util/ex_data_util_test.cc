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
using ::kmsengine::testing_util::MockRsaKey;
using ::testing::Not;

TEST(ExDataUtilTest, RsaKeyRoundtrip) {
  ASSERT_THAT(InitExternalIndices(), IsOk());

  OpenSslRsa rsa = MakeRsa();
  MockRsaKey rsa_key;
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), IsOk());

  RsaKey *actual = GetRsaKeyFromOpenSslRsa(rsa.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), &rsa_key);

  FreeExternalIndices();
}

TEST(ExDataUtilTest, HandlesNullRsaKey) {
  ASSERT_THAT(InitExternalIndices(), IsOk());

  OpenSslRsa rsa = MakeRsa();
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(nullptr, rsa.get()), IsOk());
  EXPECT_THAT(GetRsaKeyFromOpenSslRsa(rsa.get()), Not(IsOk()));

  FreeExternalIndices();
}

TEST(ExDataUtilTest, ReturnsErrorOnNullRsa) {
  ASSERT_THAT(InitExternalIndices(), IsOk());

  MockRsaKey rsa_key;
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, nullptr), Not(IsOk()));
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(nullptr, nullptr), Not(IsOk()));
  EXPECT_THAT(GetRsaKeyFromOpenSslRsa(nullptr), Not(IsOk()));

  FreeExternalIndices();
}

TEST(ExDataUtilTest, ReturnsErrorWhenRsaExternalIndiciesNotInitialized) {
  // Explicitly not calling `InitExternalIndices` here.
  OpenSslRsa rsa = MakeRsa();
  MockRsaKey rsa_key;

  EXPECT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), Not(IsOk()));
  EXPECT_THAT(AttachRsaKeyToOpenSslRsa(nullptr, rsa.get()), Not(IsOk()));

  EXPECT_THAT(GetRsaKeyFromOpenSslRsa(rsa.get()), Not(IsOk()));
}

TEST(ExDataUtilTest, EngineDataRoundtrip) {
  ASSERT_THAT(InitExternalIndices(), IsOk());

  OpenSslEngine engine = MakeEngine();
  EngineData engine_data(nullptr, {nullptr, nullptr});
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, engine.get()),
              IsOk());

  EngineData *actual = GetEngineDataFromOpenSslEngine(engine.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), &engine_data);

  FreeExternalIndices();
}

TEST(ExDataUtilTest, HandlesNullEngineData) {
  ASSERT_THAT(InitExternalIndices(), IsOk());

  OpenSslEngine engine = MakeEngine();
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()), IsOk());
  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), Not(IsOk()));

  FreeExternalIndices();
}

TEST(ExDataUtilTest, ReturnsErrorOnNullEngine) {
  ASSERT_THAT(InitExternalIndices(), IsOk());

  EngineData engine_data(nullptr, {nullptr, nullptr});
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, nullptr),
              Not(IsOk()));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, nullptr), Not(IsOk()));
  EXPECT_THAT(GetEngineDataFromOpenSslEngine(nullptr), Not(IsOk()));

  FreeExternalIndices();
}

TEST(ExDataUtilTest, ReturnsErrorWhenEngineExternalIndiciesNotInitialized) {
  // Explicitly not calling `InitExternalIndices` here.
  OpenSslEngine engine = MakeEngine();
  EngineData engine_data(nullptr, {nullptr, nullptr});

  EXPECT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, engine.get()),
              Not(IsOk()));
  EXPECT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()),
              Not(IsOk()));

  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), Not(IsOk()));
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
