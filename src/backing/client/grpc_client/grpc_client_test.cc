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

// Test fixture for testing `GrpcClient`.
//
// Instantiates a `MockKeyManagementServiceStub` and
// `MockClientContextFactory`.
class GrpcClientTest : public testing::Test {
 protected:
  GrpcClientTest()
      : stub(absl::make_unique<MockKeyManagementServiceStub>()),
        context_factory(absl::make_unique<MockClientContextFactory>()) {}
  virtual ~GrpcClientTest() = default;

  std::unique_ptr<MockKeyManagementServiceStub> stub;
  std::unique_ptr<MockClientContextFactory> context_factory;
};

class AsymmetricSignTest :
    public GrpcClientTest,
    public testing::WithParamInterface<std::tuple<std::string, DigestCase,
                                                  std::string>> {
  // Purposely empty; used to write value-parameterized tests on top of the
  // `GrpcClientTest` fixture.
};

INSTANTIATE_TEST_SUITE_P(AsymmetricSignParameters, AsymmetricSignTest,
                         Combine(ValuesIn(kSampleKeyNames),
                                 ValuesIn(kDigestCases),
                                 ValuesIn(kSampleDigests)));

TEST_P(AsymmetricSignTest, AsymmetricSignReturnsSignatureInResponse) {
  const std::string expected_signature = "my signature";
  const std::string key = std::get<0>(GetParam());
  const DigestCase digest_case = std::get<1>(GetParam());
  const std::string digest_bytes = std::get<2>(GetParam());

  google::cloud::kms::v1::AsymmetricSignResponse mock_response;
  mock_response.set_signature(expected_signature);

  EXPECT_CALL(*stub, AsymmetricSign)
      .WillOnce(DoAll(SetArgPointee</*response_param_index=*/2>(mock_response),
                      Return(Status::kOk)));

  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  StatusOr<std::string> actual = client.AsymmetricSign(key, digest_case,
                                                       digest_bytes);
  EXPECT_THAT(actual, IsOk());
  EXPECT_THAT(actual.value(), StrEq(expected_signature));
}

TEST_P(AsymmetricSignTest, AsymmetricSignSetsCorrectRequestFields) {
  const std::string expected_key = std::get<0>(GetParam());
  const DigestCase expected_digest_case = std::get<1>(GetParam());
  const std::string expected_digest_bytes = std::get<2>(GetParam());

  google::cloud::kms::v1::AsymmetricSignRequest actual_request;
  EXPECT_CALL(*stub, AsymmetricSign)
      .WillOnce(DoAll(SaveArg</*request_param_index=*/1>(&actual_request),
                      Return(Status::kOk)));

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

  EXPECT_CALL(*stub, AsymmetricSign)
      .WillOnce(Return(Status(StatusCode::kCancelled, "cancelled")));

  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  StatusOr<std::string> actual = client.AsymmetricSign(key, digest_case,
                                                       digest_bytes);
  EXPECT_THAT(actual, Not(IsOk()));
  EXPECT_THAT(actual.status().code(), StatusCode::kCancelled);
  EXPECT_THAT(actual.status().message(), "cancelled");
}

class GetPublicKeyTest :
    public GrpcClientTest,
    public testing::WithParamInterface<std::string> {
  // Purposely empty; used to write value-parameterized tests on top of the
  // `GrpcClientTest` fixture.
};

INSTANTIATE_TEST_SUITE_P(GetPublicKeyParameters, GetPublicKeyTest,
                         ValuesIn(kSampleKeyNames));

TEST_P(GetPublicKeyTest, GetPublicKeyReturnsResponse) {
  const std::string key = GetParam();

  google::cloud::kms::v1::PublicKey mock_response;
  mock_response.set_pem("my public key");
  mock_response.set_algorithm(
      google::cloud::kms::v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);

  EXPECT_CALL(*stub, GetPublicKey)
      .WillOnce(DoAll(SetArgPointee</*response_param_index=*/2>(mock_response),
                      Return(Status::kOk)));

  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  StatusOr<PublicKey> actual = client.GetPublicKey(key);
  EXPECT_THAT(actual, IsOk());
  EXPECT_THAT(actual.value().pem(), StrEq("my public key"));
  EXPECT_EQ(actual.value().algorithm(),
            CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256);
}

TEST_P(GetPublicKeyTest, GetPublicKeyReturnsErrors) {
  const std::string key = GetParam();

  EXPECT_CALL(*stub, GetPublicKey)
      .WillOnce(Return(Status(StatusCode::kCancelled, "cancelled")));

  EXPECT_CALL(*context_factory, MakeContext);

  GrpcClient client(std::move(stub), std::move(context_factory));
  StatusOr<PublicKey> actual = client.GetPublicKey(key);
  EXPECT_THAT(actual, Not(IsOk()));
  EXPECT_THAT(actual.status().code(), StatusCode::kCancelled);
  EXPECT_THAT(actual.status().message(), "cancelled");
}

}  // namespace
}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine
