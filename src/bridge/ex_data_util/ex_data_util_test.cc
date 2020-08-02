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
#include "src/testing_util/mock_crypto_key_handle.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockCryptoKeyHandle;
using ::testing::Not;

TEST(ExDataUtilTest, RsaCryptoKeyHandleRoundtrip) {
  ASSERT_THAT(InitExternalIndicies(), IsOk());

  auto rsa = MakeRsa();
  MockCryptoKeyHandle handle;
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(&handle, rsa.get()), IsOk());

  auto actual = GetCryptoKeyHandleFromOpenSslRsa(rsa.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), &handle);

  FreeExternalIndicies();
}

TEST(ExDataUtilTest, HandlesNullCryptoKeyHandle) {
  ASSERT_THAT(InitExternalIndicies(), IsOk());

  auto rsa = MakeRsa();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa.get()), IsOk());
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslRsa(rsa.get()), Not(IsOk()));

  FreeExternalIndicies();
}

TEST(ExDataUtilTest, ReturnsErrorWhenRsaExternalIndiciesNotInitialized) {
  // Explicitly not calling `InitExternalIndices` here.
  auto rsa = MakeRsa();
  MockCryptoKeyHandle handle;

  EXPECT_THAT(AttachCryptoKeyHandleToOpenSslRsa(&handle, rsa.get()),
              Not(IsOk()));
  EXPECT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa.get()),
              Not(IsOk()));

  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslRsa(rsa.get()), Not(IsOk()));
}

TEST(ExDataUtilTest, EngineDataRoundtrip) {
  ASSERT_THAT(InitExternalIndicies(), IsOk());

  auto engine = MakeEngine();
  EngineData engine_data(nullptr, {nullptr, nullptr});
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, engine.get()),
              IsOk());

  auto actual = GetEngineDataFromOpenSslEngine(engine.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), &engine_data);

  FreeExternalIndicies();
}

TEST(ExDataUtilTest, HandlesNullEngineData) {
  ASSERT_THAT(InitExternalIndicies(), IsOk());

  auto engine = MakeEngine();
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()), IsOk());
  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), Not(IsOk()));

  FreeExternalIndicies();
}

TEST(ExDataUtilTest, ReturnsErrorWhenEngineExternalIndiciesNotInitialized) {
  // Explicitly not calling `InitExternalIndices` here.
  auto engine = MakeEngine();
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
