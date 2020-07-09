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
 * FromRpcErrorToStatus tests copyright 2019 Google LLC
 *
 *     Source: https://github.com/googleapis/google-cloud-cpp/
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

#include "absl/strings/str_cat.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "src/backing/status/status.h"


namespace kmsengine {
namespace backing {
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

constexpr DigestCase kDigestCases[] = {
  DigestCase::kSha256,
  DigestCase::kSha384,
  DigestCase::kSha512,
};

const std::string kSampleDigests[] = {
  // Example SHA-256 digest of "hello world" for testing.
  "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "an arbitrary digest",
  "",
};

class MakeDigestTest : public
    testing::TestWithParam<std::tuple<DigestCase, std::string>> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(
    DigestParameters, MakeDigestTest,
    Combine(ValuesIn(kDigestCases), ValuesIn(kSampleDigests)));

TEST_P(MakeDigestTest, MakeDigest) {
  auto expected_digest_type = std::get<0>(GetParam());
  auto expected_digest_bytes = std::get<1>(GetParam());

  auto actual = MakeDigest(expected_digest_type, expected_digest_bytes);
  EXPECT_EQ(FromProtoToDigestCase(actual.digest_case()), expected_digest_type);
  EXPECT_THAT(GetDigestBytes(actual), StrEq(expected_digest_bytes));
}

TEST(FromRpcErrorToStatusTest, ProtoValidCode) {
  struct {
    grpc::StatusCode grpc;
    StatusCode expected;
  } expected_codes[]{
      {grpc::StatusCode::OK, StatusCode::kOk},
      {grpc::StatusCode::CANCELLED, StatusCode::kCancelled},
      {grpc::StatusCode::UNKNOWN, StatusCode::kUnknown},
      {grpc::StatusCode::INVALID_ARGUMENT, StatusCode::kInvalidArgument},
      {grpc::StatusCode::DEADLINE_EXCEEDED, StatusCode::kDeadlineExceeded},
      {grpc::StatusCode::NOT_FOUND, StatusCode::kNotFound},
      {grpc::StatusCode::ALREADY_EXISTS, StatusCode::kAlreadyExists},
      {grpc::StatusCode::PERMISSION_DENIED, StatusCode::kPermissionDenied},
      {grpc::StatusCode::UNAUTHENTICATED, StatusCode::kUnauthenticated},
      {grpc::StatusCode::RESOURCE_EXHAUSTED, StatusCode::kResourceExhausted},
      {grpc::StatusCode::FAILED_PRECONDITION, StatusCode::kFailedPrecondition},
      {grpc::StatusCode::ABORTED, StatusCode::kAborted},
      {grpc::StatusCode::OUT_OF_RANGE, StatusCode::kOutOfRange},
      {grpc::StatusCode::UNIMPLEMENTED, StatusCode::kUnimplemented},
      {grpc::StatusCode::INTERNAL, StatusCode::kInternal},
      {grpc::StatusCode::UNAVAILABLE, StatusCode::kUnavailable},
      {grpc::StatusCode::DATA_LOSS, StatusCode::kDataLoss},
  };

  for (auto const& codes : expected_codes) {
    std::string const message = "test message";
    grpc::Status original(codes.grpc, message);
    auto const expected = Status(codes.expected, message);
    auto const actual = FromRpcErrorToStatus(original);
    EXPECT_EQ(expected, actual);
  }
}

}  // namespace
}  // namespace backing
}  // namespace kmsengine
