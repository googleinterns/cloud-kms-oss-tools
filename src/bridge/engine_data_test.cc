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
#include "src/bridge/engine_data.h"
#include "src/testing_util/mock_client.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::testing_util::MockClient;
using ::testing::StrEq;

TEST(EngineDataTest, ClientRoundtrip) {
  auto client = absl::make_unique<MockClient>();
  EXPECT_CALL(*client, GetPublicKey);

  auto rsa_method = MakeRsaMethod("", 0);
  EngineData engine_data(std::move(client), std::move(rsa_method));

  // Check that we got the client back using a mock call.
  (void)engine_data.client()->GetPublicKey("");
}

TEST(EngineDataTest, RsaMethodRoundtrip) {
  auto client = absl::make_unique<MockClient>();
  auto rsa_method = MakeRsaMethod("my RSA method", 0);
  EngineData engine_data(std::move(client), std::move(rsa_method));

  EXPECT_THAT(RSA_meth_get0_name(engine_data.rsa_method()),
              StrEq("my RSA method"));
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
