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

#include <memory>
#include <tuple>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/memory/memory.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/grpc_client/grpc_client.h"
#include "src/backing/client/grpc_client/proto_util.h"
#include "src/backing/status/status.h"
#include "src/testing_util/mock_client_context_factory.h"
#include "src/testing_util/mock_key_management_service_stub.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {
namespace {

using ::kmsengine::testing_util::EqualsProto;
using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockClientContextFactory;
using ::kmsengine::testing_util::MockKeyManagementServiceStub;
using ::testing::Combine;
using ::testing::DoAll;
using ::testing::Not;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::ValuesIn;

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

const std::string kSampleKeyNames[] = {
  "/projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY"
       "/cryptoKeyVersions/VERSION",
  "another arbitrary key name",
  "",
};

const std::string kSampleSignatures[] = {
  // Random 2048-bit / 256-byte string.
  absl::HexStringToBytes(
      "650c9f2e6701e3fe73d3054904a9a4bbdb96733f1c4c743ef573ad6ac14c5a3bf8a4731f"
      "6e6276faea5247303677fb8dbdf24ff78e53c25052cdca87eecfee85476bcb8a05cb9a1e"
      "fef7cb87dd68223e117ce800ac46177172544757a487be32f5ab8fe0879fa8add78be465"
      "ea8f8d5acf977e9f1ae36d4d47816ea6ed41372b650c9f2e6701e3fe73d3054904a9a4bb"
      "db96733f1c4c743ef573ad6ac14c5a3bf8a4731f6e6276faea5247303677fb8dbdf24ff7"
      "8e53c25052cdca87eecfee85476bcb8a05cb9a1efef7cb87dd68223e117ce800ac461771"
      "72544757a487be32f5ab8fe0879fa8add78be465ea8f8d5acf977e9f1ae36d4d47816ea6"
      "ed41372b"),
  // Check that signing operations handle signatures containing null bytes.
  absl::HexStringToBytes(
      "bababa"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "ababab"),
  // Ends with null bytes.
  absl::HexStringToBytes(
      "bababa"
      "0000000000000000000000000000000000000000000000000000000000000000000000"),
  // Starts with null bytes and ends with non-null bytes.
  absl::HexStringToBytes(
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "ababab"),
  // Check all null string.
  absl::HexStringToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000000000"),
  // Check some arbitrary short string.
  "my unique signature",
  // Check empty string.
  "",
};

class AsymmetricSignTest : public
    testing::TestWithParam<std::tuple<std::string, DigestCase, std::string>> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(AsymmetricSignParameters, AsymmetricSignTest,
                         Combine(ValuesIn(kSampleKeyNames),
                                 ValuesIn(kDigestCases),
                                 ValuesIn(kSampleDigests),
                                 ValuesIn(kSampleSignatures)));

TEST_P(AsymmetricSignTest, AsymmetricSignReturnsSignatureInResponse) {
  const std::string key = std::get<0>(GetParam());
  const DigestCase digest_case = std::get<1>(GetParam());
  const std::string digest_bytes = std::get<2>(GetParam());
  const std::string expected_signature = std::get<3>(GetParam());

  google::cloud::kms::v1::AsymmetricSignResponse mock_response;
  mock_response.set_signature(expected_signature.data(),
                              expected_signature.length());

  auto stub = absl::make_unique<MockKeyManagementServiceStub>();
  EXPECT_CALL(*stub, AsymmetricSign)
      .WillOnce(DoAll(SetArgPointee</*response_param_index=*/2>(mock_response),
                      Return(Status())));

  auto context_factory = absl::make_unique<MockClientContextFactory>();
  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  auto actual = client.AsymmetricSign(key, digest_case, digest_bytes);
  EXPECT_THAT(actual, IsOk());
  EXPECT_THAT(actual.value(), StrEq(expected_signature));
}

TEST_P(AsymmetricSignTest, AsymmetricSignSetsCorrectRequestFields) {
  const std::string expected_key = std::get<0>(GetParam());
  const DigestCase expected_digest_case = std::get<1>(GetParam());
  const std::string expected_digest_bytes = std::get<2>(GetParam());

  google::cloud::kms::v1::AsymmetricSignRequest actual_request;
  auto stub = absl::make_unique<MockKeyManagementServiceStub>();
  EXPECT_CALL(*stub, AsymmetricSign)
      .WillOnce(DoAll(SaveArg</*request_param_index=*/1>(&actual_request),
                      Return(Status())));

  auto context_factory = absl::make_unique<MockClientContextFactory>();
  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  client.AsymmetricSign(expected_key, expected_digest_case,
                        expected_digest_bytes);
  EXPECT_THAT(actual_request.name(), StrEq(expected_key));
  EXPECT_THAT(actual_request.digest(),
              EqualsProto(MakeDigest(expected_digest_case,
                                     expected_digest_bytes)));
}

TEST_P(AsymmetricSignTest, AsymmetricSignReturnsErrors) {
  const std::string key = std::get<0>(GetParam());
  const DigestCase digest_case = std::get<1>(GetParam());
  const std::string digest_bytes = std::get<2>(GetParam());

  auto stub = absl::make_unique<MockKeyManagementServiceStub>();
  EXPECT_CALL(*stub, AsymmetricSign)
      .WillOnce(Return(Status(StatusCode::kCancelled, "cancelled")));

  auto context_factory = absl::make_unique<MockClientContextFactory>();
  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  auto actual = client.AsymmetricSign(key, digest_case, digest_bytes);
  EXPECT_THAT(actual, Not(IsOk()));
  EXPECT_THAT(actual.status().code(), StatusCode::kCancelled);
  EXPECT_THAT(actual.status().message(), "cancelled");
}

class GetPublicKeyTest : public testing::TestWithParam<std::string> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(GetPublicKeyParameters, GetPublicKeyTest,
                         ValuesIn(kSampleKeyNames));

TEST_P(GetPublicKeyTest, GetPublicKeyReturnsResponse) {
  const std::string key_resource_id = GetParam();

  google::cloud::kms::v1::PublicKey mock_response;
  mock_response.set_pem("my public key");
  mock_response.set_algorithm(
      google::cloud::kms::v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);

  auto stub = absl::make_unique<MockKeyManagementServiceStub>();
  EXPECT_CALL(*stub, GetPublicKey)
      .WillOnce(DoAll(SetArgPointee</*response_param_index=*/2>(mock_response),
                      Return(Status())));

  auto context_factory = absl::make_unique<MockClientContextFactory>();
  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  auto actual = client.GetPublicKey(key_resource_id);
  EXPECT_THAT(actual, IsOk());
  EXPECT_THAT(actual.value().pem(), StrEq("my public key"));
  EXPECT_EQ(actual.value().algorithm(),
            CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256);
}

TEST_P(GetPublicKeyTest, GetPublicKeyReturnsErrors) {
  const std::string key = GetParam();

  auto stub = absl::make_unique<MockKeyManagementServiceStub>();
  EXPECT_CALL(*stub, GetPublicKey)
      .WillOnce(Return(Status(StatusCode::kCancelled, "cancelled")));

  auto context_factory = absl::make_unique<MockClientContextFactory>();
  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  auto actual = client.GetPublicKey(key);
  EXPECT_THAT(actual, Not(IsOk()));
  EXPECT_THAT(actual.status().code(), StatusCode::kCancelled);
  EXPECT_THAT(actual.status().message(), "cancelled");
}

}  // namespace
}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine
