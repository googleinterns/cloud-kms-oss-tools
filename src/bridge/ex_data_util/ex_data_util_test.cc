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

using ::kmsengine::backing::CryptoKeyHandle;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockCryptoKeyHandle;
using ::testing::Not;

TEST(UninitializedExDataUtilTest, RsaReturnsError) {
  // Explicitly not using TEST_F here so we do not call `InitExternalIndices`.
  OpenSslRsa rsa = MakeRsa();
  MockCryptoKeyHandle handle;

  EXPECT_THAT(AttachCryptoKeyHandleToOpenSslRsa(&handle, rsa.get()),
              Not(IsOk()));
  EXPECT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa.get()),
              Not(IsOk()));

  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslRsa(rsa.get()), Not(IsOk()));
}

TEST(UninitializedExDataUtilTest, EcKeyReturnsError) {
  // Explicitly not using TEST_F here so we do not call `InitExternalIndices`.
  OpenSslEcKey ec_key = MakeEcKey();
  MockCryptoKeyHandle handle;

  EXPECT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(&handle, ec_key.get()),
              Not(IsOk()));
  EXPECT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(nullptr, ec_key.get()),
              Not(IsOk()));

  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslEcKey(ec_key.get()), Not(IsOk()));
}

TEST(UninitializedExDataUtilTest, EngineReturnsError) {
  // Explicitly not using TEST_F here so we do not call `InitExternalIndices`.
  OpenSslEngine engine = MakeEngine();
  EngineData engine_data(nullptr, {nullptr, nullptr});

  EXPECT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, engine.get()),
              Not(IsOk()));
  EXPECT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()),
              Not(IsOk()));

  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), Not(IsOk()));
}

// Test fixture for ex_data_util functions which calls `InitExternalIndices` at
// the top of the test case and frees the external index system at the end of
// the test case.
class InitializedExDataUtilTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(InitExternalIndices(), IsOk());
  }

  void TearDown() override {
    FreeExternalIndices();
  }
};

TEST_F(InitializedExDataUtilTest, RsaCryptoKeyHandleRoundtrip) {
  OpenSslRsa rsa = MakeRsa();
  MockCryptoKeyHandle handle;
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(&handle, rsa.get()), IsOk());

  StatusOr<CryptoKeyHandle *> actual =
      GetCryptoKeyHandleFromOpenSslRsa(rsa.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), &handle);
}

TEST_F(InitializedExDataUtilTest, RsaHandlesNullCryptoKeyHandle) {
  OpenSslRsa rsa = MakeRsa();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa.get()), IsOk());
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslRsa(rsa.get()), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, RsaReturnsErrorOnNullRsa) {
  MockCryptoKeyHandle handle;
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(&handle, nullptr),
              Not(IsOk()));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, nullptr),
              Not(IsOk()));
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslRsa(nullptr), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, RsaUniquePtrCryptoKeyHandleRoundtrip) {
  OpenSslRsa rsa = MakeRsa();
  auto handle = absl::make_unique<MockCryptoKeyHandle>();
  auto expected = handle.get();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(std::move(handle), rsa.get()),
              IsOk());

  StatusOr<CryptoKeyHandle *> actual =
      GetCryptoKeyHandleFromOpenSslRsa(rsa.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), expected);
}

TEST_F(InitializedExDataUtilTest, RsaUniquePtrHandlesNullCryptoKeyHandle) {
  OpenSslRsa rsa = MakeRsa();
  std::unique_ptr<CryptoKeyHandle> handle(nullptr);
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(std::move(handle), rsa.get()),
              IsOk());
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslRsa(rsa.get()), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, RsaUniquePtrReturnsErrorOnNullRsa) {
  auto handle = absl::make_unique<MockCryptoKeyHandle>();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(std::move(handle), nullptr),
              Not(IsOk()));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(nullptr, nullptr),
              Not(IsOk()));
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslRsa(nullptr), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, EcKeyCryptoKeyHandleRoundtrip) {
  OpenSslEcKey ec_key = MakeEcKey();
  MockCryptoKeyHandle handle;
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(&handle, ec_key.get()),
              IsOk());

  StatusOr<CryptoKeyHandle *> actual =
      GetCryptoKeyHandleFromOpenSslEcKey(ec_key.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), &handle);
}

TEST_F(InitializedExDataUtilTest, EcKeyHandlesNullCryptoKeyHandle) {
  OpenSslEcKey ec_key = MakeEcKey();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(nullptr, ec_key.get()),
              IsOk());
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslEcKey(ec_key.get()), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, EcKeyReturnsErrorOnNullEcKey) {
  MockCryptoKeyHandle handle;
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(&handle, nullptr),
              Not(IsOk()));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(nullptr, nullptr),
              Not(IsOk()));
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslEcKey(nullptr), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, EcKeyUniquePtrCryptoKeyHandleRoundtrip) {
  OpenSslEcKey ec_key = MakeEcKey();
  auto handle = absl::make_unique<MockCryptoKeyHandle>();
  auto expected = handle.get();
  ASSERT_THAT(
      AttachCryptoKeyHandleToOpenSslEcKey(std::move(handle), ec_key.get()),
      IsOk());

  StatusOr<CryptoKeyHandle *> actual =
      GetCryptoKeyHandleFromOpenSslEcKey(ec_key.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), expected);
}

TEST_F(InitializedExDataUtilTest, EcKeyUniquePtrHandlesNullCryptoKeyHandle) {
  OpenSslEcKey ec_key = MakeEcKey();
  std::unique_ptr<CryptoKeyHandle> handle(nullptr);
  ASSERT_THAT(
      AttachCryptoKeyHandleToOpenSslEcKey(std::move(handle), ec_key.get()),
      IsOk());
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslEcKey(ec_key.get()), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, EcKeyUniquePtrReturnsErrorOnNullEcKey) {
  auto handle = absl::make_unique<MockCryptoKeyHandle>();
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(std::move(handle), nullptr),
              Not(IsOk()));
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslEcKey(nullptr, nullptr),
              Not(IsOk()));
  EXPECT_THAT(GetCryptoKeyHandleFromOpenSslEcKey(nullptr), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, EngineDataRoundtrip) {
  OpenSslEngine engine = MakeEngine();
  EngineData engine_data(nullptr, {nullptr, nullptr}, {nullptr, nullptr});
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, engine.get()),
              IsOk());

  StatusOr<EngineData *> actual = GetEngineDataFromOpenSslEngine(engine.get());
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), &engine_data);
}

TEST_F(InitializedExDataUtilTest, EngineHandlesNullEngineData) {
  OpenSslEngine engine = MakeEngine();
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()), IsOk());
  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), Not(IsOk()));
}

TEST_F(InitializedExDataUtilTest, EngineReturnsErrorOnNullEngine) {
  EngineData engine_data(nullptr, {nullptr, nullptr}, {nullptr, nullptr});
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, nullptr),
              Not(IsOk()));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(nullptr, nullptr), Not(IsOk()));
  EXPECT_THAT(GetEngineDataFromOpenSslEngine(nullptr), Not(IsOk()));
}

TEST(ExDataUtilTest, ReturnsErrorWhenEngineExternalIndiciesNotInitialized) {
  // Explicitly not calling `InitExternalIndices` here.
  OpenSslEngine engine = MakeEngine();
  EngineData engine_data(nullptr, {nullptr, nullptr}, {nullptr, nullptr});

  EXPECT_THAT(AttachEngineDataToOpenSslEngine(&engine_data, engine.get()),
              Not(IsOk()));
  EXPECT_THAT(AttachEngineDataToOpenSslEngine(nullptr, engine.get()),
              Not(IsOk()));

  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine.get()), Not(IsOk()));
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
