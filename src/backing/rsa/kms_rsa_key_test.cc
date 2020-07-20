/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/memory/memory.h"
#include "src/backing/rsa/kms_rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/testing_util/mock_client.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace backing {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockClient;
using ::testing::_;
using ::testing::Not;
using ::testing::Return;
using ::testing::StrEq;

constexpr auto kSampleKeyResourceId = "resource_id";

TEST(KmsRsaKeyTest, SignSuccess) {
  auto expected_signature = "signature";
  auto client = std::make_shared<MockClient>();
  EXPECT_CALL(*client, AsymmetricSign(kSampleKeyResourceId, _, _))
      .Times(1)
      .WillOnce(Return(StatusOr<std::string>(expected_signature)));

  KmsRsaKey key(kSampleKeyResourceId, client);
  auto result = key.Sign(DigestCase::kSha256, "my digest");
  EXPECT_THAT(result, IsOk());
  EXPECT_EQ(result.value(), expected_signature);
}

TEST(KmsRsaKeyTest, SignFailure) {
  auto expected_status = Status(StatusCode::kCancelled, "cancelled");
  auto client = std::make_shared<MockClient>();
  EXPECT_CALL(*client, AsymmetricSign(kSampleKeyResourceId, _, _))
      .Times(1)
      .WillOnce(Return(StatusOr<std::string>(expected_status)));

  KmsRsaKey key(kSampleKeyResourceId, client);
  auto result = key.Sign(DigestCase::kSha256, "my digest");
  EXPECT_THAT(result, Not(IsOk()));
  EXPECT_EQ(result.status(), expected_status);
}

TEST(KmsRsaKeyTest, GetPublicKeySuccess) {
  PublicKey expected("my public key",
                     CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256);
  auto client = std::make_shared<MockClient>();
  EXPECT_CALL(*client, GetPublicKey(kSampleKeyResourceId))
      .Times(1)
      .WillOnce(Return(StatusOr<PublicKey>(expected)));

  KmsRsaKey key(kSampleKeyResourceId, client);
  auto result = key.GetPublicKey();
  EXPECT_THAT(result, IsOk());
  EXPECT_EQ(result.value(), expected);
}

TEST(KmsRsaKeyTest, GetPublicKeyFailure) {
  auto expected_status = Status(StatusCode::kCancelled, "cancelled");
  auto client = std::make_shared<MockClient>();
  EXPECT_CALL(*client, GetPublicKey(kSampleKeyResourceId))
      .Times(1)
      .WillOnce(Return(StatusOr<PublicKey>(expected_status)));

  KmsRsaKey key(kSampleKeyResourceId, client);
  auto result = key.GetPublicKey();
  EXPECT_THAT(result, Not(IsOk()));
  EXPECT_EQ(result.status(), expected_status);
}

}  // namespace
}  // namespace backing
}  // namespace kmsengine
