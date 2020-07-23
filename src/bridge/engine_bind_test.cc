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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <openssl/engine.h>

#include "absl/memory/memory.h"
#include "src/bridge/engine_bind.h"
#include "src/bridge/engine_name.h"
#include "src/bridge/rsa/rsa.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/testing_util/openssl_assertions.h"
#include "src/testing_util/mock_rsa_key.h"
#include "src/testing_util/mock_client.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockRsaKey;
using ::kmsengine::testing_util::MockClient;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::StrEq;

TEST(EngineBindTest, InitializesExpectedEngineStructFields) {
  auto engine = MakeEngine();

  ASSERT_OPENSSL_SUCCESS(EngineBind(engine.get(), nullptr));

  EXPECT_THAT(ENGINE_get_id(engine.get()), StrEq(kEngineId));
  EXPECT_THAT(ENGINE_get_name(engine.get()), StrEq(kEngineName));
  EXPECT_THAT(ENGINE_get_init_function(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_finish_function(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_destroy_function(engine.get()), Not(IsNull()));
  EXPECT_TRUE(ENGINE_get_flags(engine.get()) & ENGINE_FLAGS_NO_REGISTER_ALL)
      << "ENGINE_FLAGS_NO_REGISTER_ALL should be set on EngineBind since "
         "Engine does not support all cryptography operations";
}

TEST(EngineBindTest, InitializesExternalDataSystem) {
  auto engine = MakeEngine();
  ASSERT_OPENSSL_SUCCESS(EngineBind(engine.get(), nullptr));

  // Indirectly check that the external index system was initialized by
  // performing attach operations and seeing if they succeed.
  auto rsa = MakeRsa();
  MockRsaKey rsa_key;
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), IsOk())
      << "ex_data_util RSA operations should have been initialized after "
         "EngineBind";

  auto client = absl::make_unique<MockClient>();
  auto rsa_method = rsa::MakeKmsRsaMethod();
  EngineData data(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(&data, engine.get()), IsOk())
      << "ex_data_util ENGINE operations should have been initialized after "
         "EngineBind";
}

TEST(EngineDestroyTest, CleansUpExternalDataSystem) {
  ENGINE *engine = ENGINE_new();
  ASSERT_OPENSSL_SUCCESS(EngineBind(engine, nullptr));
  ENGINE_free(engine);  // `EngineDestroy` should be called by free.

  // Indirectly check that the external index system was cleaned up by
  // performing attach operations and seeing if they fail.
  auto rsa = MakeRsa();
  MockRsaKey rsa_key;
  ASSERT_THAT(AttachRsaKeyToOpenSslRsa(&rsa_key, rsa.get()), Not(IsOk()))
      << "ex_data_util RSA operations should have been cleaned up after "
         "EngineDestroy";

  auto fake_engine = MakeEngine();
  auto client = absl::make_unique<MockClient>();
  auto rsa_method = rsa::MakeKmsRsaMethod();
  EngineData data(std::move(client), std::move(rsa_method));
  ASSERT_THAT(AttachEngineDataToOpenSslEngine(&data, fake_engine.get()),
              Not(IsOk()))
      << "ex_data_util ENGINE operations should have been cleaned up after "
         "EngineDestroy";
}

// Fixture for testing `EngineInit`. `EngineInit` can only be called on
// engines that have been bound, so this fixture instantiates a new OpenSSL
// `ENGINE` and binds the Cloud KMS OpenSSL Engine to it. Users can then call
// the `ENGINE_init` function from OpenSSL on the bound `ENGINE`, which should
// delegate to our engine's implementation of `EngineInit`.
class EngineInitTest : public ::testing::Test {
 protected:
  EngineInitTest() : engine_(MakeEngine()) {}

  void SetUp() override {
    ASSERT_THAT(engine(), Not(IsNull()));
    ASSERT_OPENSSL_SUCCESS(EngineBind(engine(), nullptr));
  }

  // Returns a raw pointer to a bound `ENGINE` struct.
  ENGINE *engine() const { return engine_.get(); }

 private:
  const OpenSslEngine engine_;
};

TEST_F(EngineInitTest, EngineDataRoundtrip) {
  ASSERT_OPENSSL_SUCCESS(ENGINE_init(engine()));

  auto engine_data_or = GetEngineDataFromOpenSslEngine(engine());
  ASSERT_THAT(engine_data_or, IsOk());
  auto engine_data = engine_data_or.value();

  ASSERT_THAT(engine_data, Not(IsNull()));
  ASSERT_THAT(engine_data->rsa_method(), Not(IsNull()));

  ASSERT_OPENSSL_SUCCESS(ENGINE_finish(engine()));

  ASSERT_THAT(GetEngineDataFromOpenSslEngine(engine()), Not(IsOk()))
      << "EngineData attached to ENGINE struct should have been nulled-out "
         "on EngineDestroy";
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
