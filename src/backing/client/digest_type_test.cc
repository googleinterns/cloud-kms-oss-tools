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
#include <google/cloud/kms/v1/service.pb.h>

#include "src/backing/client/digest_type.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

using ProtoDigestCase = google::cloud::kms::v1::Digest::DigestCase;
using DigestTypeUnderlying = std::underlying_type<DigestType>;

TEST(DigestTypeTest, UnderlyingEnumValueMatchesProtoDefinitions) {
  EXPECT_EQ(static_cast<DigestTypeUnderlying>(DigestType::kSha256),
            ProtoDigestCase::kSha256);
  EXPECT_EQ(static_cast<DigestTypeUnderlying>(DigestType::kSha384),
            ProtoDigestCase::kSha384);
  EXPECT_EQ(static_cast<DigestTypeUnderlying>(DigestType::kSha512),
            ProtoDigestCase::kSha512);
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
