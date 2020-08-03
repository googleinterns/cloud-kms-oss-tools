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

#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/rsa.h>

#include "absl/memory/memory.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/testing_util/mock_client.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::testing_util::MockClient;
using ::testing::StrEq;

TEST(EngineDataTest, ClientRoundtrip) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey("hello world"));

  EngineData engine_data(std::move(client),
                         OpenSslRsaMethod(nullptr, nullptr),
                         OpenSslEcKeyMethod(nullptr, nullptr));

  // Check that we got the same client back using a mock call.
  (void)engine_data.client().GetPublicKey("hello world");
}

TEST(EngineDataTest, RsaMethodRoundtrip) {
  constexpr auto kRsaMethodName = "my RSA method";
  EngineData engine_data(nullptr,
                         MakeRsaMethod(kRsaMethodName, /*rsa_flags=*/0),
                         OpenSslEcKeyMethod(nullptr, nullptr));

  // Check that we got the same `RSA_METHOD` back by checking the name of
  // the returned `RSA_METHOD`.
  EXPECT_THAT(RSA_meth_get0_name(engine_data.rsa_method()),
              StrEq(kRsaMethodName));
}

TEST(EngineDataTest, EcKeyMethodRoundtrip) {
  const EC_KEY_METHOD *default_ec_key_method = EC_KEY_OpenSSL();
  EngineData engine_data(nullptr,
                         OpenSslRsaMethod(nullptr, nullptr),
                         MakeEcKeyMethod(default_ec_key_method));

  // Check that we got the same `EC_KEY_METHOD` back by checking that function
  // pointers match.
  int (*actual_keygen_function)(EC_KEY *key) = nullptr;
  EC_KEY_METHOD_get_keygen(engine_data.ec_key_method(),
                           &actual_keygen_function);

  int (*expected_keygen_function)(EC_KEY *key) = nullptr;
  EC_KEY_METHOD_get_keygen(default_ec_key_method, &expected_keygen_function);

  EXPECT_EQ(actual_keygen_function, expected_keygen_function);
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
