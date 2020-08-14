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

#include "absl/memory/memory.h"
#include "src/bridge/engine_bind.h"
#include "src/bridge/engine_name.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/testing_util/openssl_assertions.h"
#include "src/testing_util/mock_crypto_key_handle.h"
#include "src/testing_util/mock_client.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockCryptoKeyHandle;
using ::kmsengine::testing_util::MockClient;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::StrEq;

TEST(EngineBindTest, InitializesExpectedEngineStructFields) {
  OpenSslEngine engine = MakeEngine();

  ASSERT_OPENSSL_SUCCESS(EngineBind(engine.get(), nullptr));

  EXPECT_THAT(ENGINE_get_id(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_name(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_init_function(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_finish_function(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_load_pubkey_function(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_load_privkey_function(engine.get()), Not(IsNull()));
  EXPECT_THAT(ENGINE_get_destroy_function(engine.get()), Not(IsNull()));
  EXPECT_TRUE(ENGINE_get_flags(engine.get()) & ENGINE_FLAGS_NO_REGISTER_ALL)
      << "ENGINE_FLAGS_NO_REGISTER_ALL should be set on EngineBind since "
         "Engine does not support all cryptography operations";
}

TEST(EngineBindTest, InitializesExternalDataSystem) {
  OpenSslEngine engine = MakeEngine();
  ASSERT_OPENSSL_SUCCESS(EngineBind(engine.get(), nullptr));

  // Indirectly check that the external index system was initialized by
  // performing attach operations and seeing if they succeed.
  OpenSslRsa rsa = MakeRsa();
  MockCryptoKeyHandle handle;
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(&handle, rsa.get()), IsOk())
      << "ex_data_util RSA operations should have been initialized after "
         "EngineBind";

  EngineData *data = new EngineData(absl::make_unique<MockClient>(),
                                    OpenSslRsaMethod(nullptr, nullptr),
                                    OpenSslEcKeyMethod(nullptr, nullptr));
  EXPECT_THAT(AttachEngineDataToOpenSslEngine(data, engine.get()), IsOk())
      << "ex_data_util ENGINE operations should have been initialized after "
         "EngineBind";
}

TEST(EngineInitTest, EngineDataRoundtrip) {
  ENGINE *engine = ENGINE_new();
  ASSERT_THAT(engine, Not(IsNull()));

  ASSERT_OPENSSL_SUCCESS(EngineBind(engine, nullptr));
  ASSERT_OPENSSL_SUCCESS(ENGINE_init(engine));

  ASSERT_THAT(GetEngineDataFromOpenSslEngine(engine), IsOk());

  ASSERT_OPENSSL_SUCCESS(ENGINE_finish(engine));
  ASSERT_OPENSSL_SUCCESS(ENGINE_free(engine));

  EXPECT_THAT(GetEngineDataFromOpenSslEngine(engine), Not(IsOk()))
      << "EngineData attached to ENGINE struct should have been nulled-out "
         "on EngineDestroy";
}

TEST(EngineDestroyTest, CleansUpExternalDataSystem) {
  ENGINE *engine = ENGINE_new();
  ASSERT_OPENSSL_SUCCESS(EngineBind(engine, nullptr));
  ENGINE_free(engine);  // `EngineDestroy` should be called by free.

  // Indirectly check that the external index system was cleaned up by
  // performing attach operations and seeing if they fail.
  OpenSslRsa rsa = MakeRsa();
  MockCryptoKeyHandle handle;
  ASSERT_THAT(AttachCryptoKeyHandleToOpenSslRsa(&handle, rsa.get()),
              Not(IsOk()))
      << "ex_data_util RSA operations should have been cleaned up after "
         "EngineDestroy";

  OpenSslEngine fake_engine = MakeEngine();
  EngineData *data = new EngineData(absl::make_unique<MockClient>(),
                                    OpenSslRsaMethod(nullptr, nullptr),
                                    OpenSslEcKeyMethod(nullptr, nullptr));
  EXPECT_THAT(AttachEngineDataToOpenSslEngine(data, fake_engine.get()),
              Not(IsOk()))
      << "ex_data_util ENGINE operations should have been cleaned up after "
         "EngineDestroy";
}
}  // namespace
}  // namespace bridge
}  // namespace kmsengine
