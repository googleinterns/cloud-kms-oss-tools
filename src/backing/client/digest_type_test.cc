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

#include <google/cloud/kms/v1/service.pb.h>
#include <gtest/gtest.h>

#include "src/backing/client/digest_type.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

// Helper function for casting a `DigestType` to its underlying type.
inline std::underlying_type<DigestType>::type CastDigest(DigestType digest) {
  return static_cast<std::underlying_type<DigestType>::type>(digest);
}

using ProtoDigestCase = google::cloud::kms::v1::Digest::DigestCase;

TEST(DigestTypeTest, UnderlyingEnumValueMatchesProtoDefinitions) {
  EXPECT_EQ(CastDigest(DigestType::kSha256), ProtoDigestCase::kSha256);
  EXPECT_EQ(CastDigest(DigestType::kSha384), ProtoDigestCase::kSha384);
  EXPECT_EQ(CastDigest(DigestType::kSha512), ProtoDigestCase::kSha512);
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
