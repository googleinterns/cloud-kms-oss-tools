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
 *
 * Modifications copyright 2020 Google LLC
 *
 *    - Renamed namespaces and file includes
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

#include <string>
#include <tuple>

#include <gmock/gmock.h>
#include <google/cloud/kms/v1/resources.grpc.pb.h>
#include <google/cloud/kms/v1/resources.pb.h>
#include <google/cloud/kms/v1/service.grpc.pb.h>
#include <google/cloud/kms/v1/service.pb.h>
#include <grpcpp/grpcpp.h>

#include "absl/strings/str_cat.h"
#include "src/backing/client/proto_util/proto_make.h"

namespace kmsengine {
namespace backing {
namespace proto_util {
namespace {

using ::testing::ValuesIn;
using ::testing::Combine;
using ::testing::StrEq;

// Gets the underlying `bytes` attached to a `Digest` protobuf.
std::string GetDigestBytes(google::cloud::kms::v1::Digest digest) {
  switch (digest.digest_case()) {
    case google::cloud::kms::v1::Digest::DigestCase::kSha256:
      return digest.sha256();
    case google::cloud::kms::v1::Digest::DigestCase::kSha384:
      return digest.sha384();
    case google::cloud::kms::v1::Digest::DigestCase::kSha512:
      return digest.sha512();
    default:
      return "";
  }
}

constexpr google::cloud::kms::v1::Digest::DigestCase kDigestCases[] = {
  google::cloud::kms::v1::Digest::DigestCase::kSha256,
  google::cloud::kms::v1::Digest::DigestCase::kSha384,
  google::cloud::kms::v1::Digest::DigestCase::kSha512,
};

const std::string kSampleKeyNames[] = {
  absl::StrCat("/projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/",
               "cryptoKeys/KEY/cryptoKeyVersions/VERSION"),
  "another arbitrary key name",
  "",
};

const std::string kSampleDigests[] = {
  // Example SHA-256 digest of "hello world" for testing.
  "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "an arbitrary digest",
  "",
};

class MakeAsymmetricSignRequestTest : public
    testing::TestWithParam<
        std::tuple<std::string, google::cloud::kms::v1::Digest::DigestCase,
                   std::string>> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(
    AsymmetricSignRequestParameters, MakeAsymmetricSignRequestTest,
    Combine(ValuesIn(kSampleKeyNames), ValuesIn(kDigestCases),
            ValuesIn(kSampleDigests)));

TEST_P(MakeAsymmetricSignRequestTest, MakeAsymmetricSignRequest) {
  auto expected_key_name = std::get<0>(GetParam());
  auto expected_digest_type = std::get<1>(GetParam());
  auto expected_digest_bytes = std::get<2>(GetParam());

  auto actual = MakeAsymmetricSignRequest(
      expected_key_name,
      MakeDigest(expected_digest_type, expected_digest_bytes));
  EXPECT_THAT(actual.name(), StrEq(expected_key_name));
  EXPECT_TRUE(actual.has_digest());

  auto actual_digest = actual.digest();
  EXPECT_EQ(actual_digest.digest_case(), expected_digest_type);
  EXPECT_THAT(GetDigestBytes(actual_digest), StrEq(expected_digest_bytes));
}

class MakeGetPublicKeyRequestTest : public
    testing::TestWithParam<std::string> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(
    GetPublicKeyRequestParameters, MakeGetPublicKeyRequestTest,
    ValuesIn(kSampleKeyNames));

TEST_P(MakeGetPublicKeyRequestTest, MakeAsymmetricSignRequest) {
  auto expected_key_name = GetParam();

  auto actual = MakeGetPublicKeyRequest(expected_key_name);
  EXPECT_THAT(actual.name(), StrEq(expected_key_name));
}

class MakeDigestTest : public
    testing::TestWithParam<
        std::tuple<google::cloud::kms::v1::Digest::DigestCase, std::string>> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(
    DigestParameters, MakeDigestTest,
    Combine(ValuesIn(kDigestCases), ValuesIn(kSampleDigests)));

TEST_P(MakeDigestTest, MakeDigest) {
  auto expected_digest_type = std::get<0>(GetParam());
  auto expected_digest_bytes = std::get<1>(GetParam());

  auto actual = MakeDigest(expected_digest_type, expected_digest_bytes);
  EXPECT_EQ(actual.digest_case(), expected_digest_type);
  EXPECT_THAT(GetDigestBytes(actual), StrEq(expected_digest_bytes));
}

}  // namespace
}  // namespace proto_util
}  // namespace backing
}  // namespace kmsengine
