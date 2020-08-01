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

#include "google/cloud/kms/v1/service.pb.h"
#include "src/backing/client/digest_case.h"

namespace kmsengine {
namespace backing {
namespace {

using ::testing::ValuesIn;

using ProtoDigestCase = google::cloud::kms::v1::Digest::DigestCase;

// Mapping between `DigestCase` cases and their protobuf equivalents.
struct CorrespondingDigestCase {
  DigestCase actual;
  ProtoDigestCase proto;
};

constexpr CorrespondingDigestCase kDigestMapping[] = {
  {DigestCase::kSha256, ProtoDigestCase::kSha256},
  {DigestCase::kSha384, ProtoDigestCase::kSha384},
  {DigestCase::kSha512, ProtoDigestCase::kSha512},
};

class DigestCaseTest : public testing::TestWithParam<CorrespondingDigestCase> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(DigestCaseParameters, DigestCaseTest,
                         ValuesIn(kDigestMapping));

TEST_P(DigestCaseTest, UnderlyingValueMatchesProtoValues) {
  auto mapping = GetParam();
  EXPECT_EQ(DigestCaseToInt(mapping.actual), mapping.proto);
}

TEST(DigestCaseTest, ToStringIsOneToOne) {
  const std::vector<DigestCase> kDigestCases = {
    DigestCase::kSha256,
    DigestCase::kSha384,
    DigestCase::kSha512,
  };

  std::set<std::string> used_strings;
  for (auto algorithm : kDigestCases) {
    auto actual = DigestCaseToString(algorithm);
    used_strings.insert(actual);
  }

  EXPECT_EQ(used_strings.size(), kDigestCases.size())
      << "Number of unique strings should equal number of unique DigestCase "
         "enums";
}

TEST(DigestCaseTest, ToStringHandlesInvalidEnums) {
  EXPECT_EQ("UNEXPECTED_DIGEST_CASE=42",
            DigestCaseToString(static_cast<DigestCase>(42)));
}

}  // namespace
}  // namespace backing
}  // namespace kmsengine
