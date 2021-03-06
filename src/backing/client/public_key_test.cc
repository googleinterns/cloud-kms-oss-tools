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

#include "src/backing/client/public_key.h"

namespace kmsengine {
namespace backing {
namespace {

using ::testing::StrEq;

TEST(PublicKeyTest, Basic) {
  PublicKey key("my pem", CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256);
  EXPECT_THAT(key.pem(), StrEq("my pem"));
  EXPECT_EQ(key.algorithm(), CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256);
}

TEST(PublicKeyTest, Equality) {
  EXPECT_EQ(PublicKey("A", CryptoKeyVersionAlgorithm::kEcSignP256Sha256),
            PublicKey("A", CryptoKeyVersionAlgorithm::kEcSignP256Sha256))
      << "Should be equal when pem and algorithm match";

  EXPECT_NE(PublicKey("A", CryptoKeyVersionAlgorithm::kEcSignP256Sha256),
            PublicKey("B", CryptoKeyVersionAlgorithm::kEcSignP256Sha256))
      << "Should not be equal when pem does not match";

  EXPECT_NE(PublicKey("A", CryptoKeyVersionAlgorithm::kAlgorithmUnspecified),
            PublicKey("A", CryptoKeyVersionAlgorithm::kEcSignP256Sha256))
      << "Should not be equal when algorithm does not match";

  EXPECT_NE(PublicKey("A", CryptoKeyVersionAlgorithm::kEcSignP384Sha384),
            PublicKey("B", CryptoKeyVersionAlgorithm::kEcSignP256Sha256))
      << "Should not be equal when both pem and algorithm do not match";
}

}  // namespace
}  // namespace backing
}  // namespace kmsengine
