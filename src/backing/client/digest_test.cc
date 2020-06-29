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

#include "src/backing/client/digest.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

TEST(DigestTest, ConstructorSetsExpectedFieldsForSha256) {
  Digest digest(DigestType::kSha256, "my-256-digest");
  EXPECT_EQ(digest.type(), DigestType::kSha256);
  EXPECT_EQ(digest.bytes(), "my-256-digest");
}

TEST(DigestTest, ConstructorSetsExpectedFieldsForSha384) {
  Digest digest(DigestType::kSha384, "my-384-digest");
  EXPECT_EQ(digest.type(), DigestType::kSha384);
  EXPECT_EQ(digest.bytes(), "my-384-digest");
}

TEST(DigestTest, ConstructorSetsExpectedFieldsForSha512) {
  Digest digest(DigestType::kSha512, "my-512-digest");
  EXPECT_EQ(digest.type(), DigestType::kSha512);
  EXPECT_EQ(digest.bytes(), "my-512-digest");
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
