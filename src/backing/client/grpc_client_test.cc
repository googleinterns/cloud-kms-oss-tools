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
#include <google/protobuf/text_format.h>

#include "src/backing/client/grpc_client.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

using ::kmsengine::backing::client::testing_util::IsProtoEqual;

TEST(GrpcClientTest, AsymmetricSignRequestWithSha256DigestToProto) {
  Digest digest(DigestType::kSha256, "my256digest");
  AsymmetricSignRequest request("my-key", digest);
  auto actual = GrpcClient::ToProto(request);

  google::cloud::kms::v1::AsymmetricSignRequest expected;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(R"""({
    "name"": "my-key",
    "digest": {
      "sha256": "my256digest",
    }
  })""", &expected));

  EXPECT_THAT(actual, IsProtoEqual(expected));
}

TEST(GrpcClientTest, AsymmetricSignRequestWithSha384DigestToProto) {
  Digest digest(DigestType::kSha384, "my384digest");
  AsymmetricSignRequest request("my-key", digest);
  auto actual = GrpcClient::ToProto(request);

  google::cloud::kms::v1::AsymmetricSignRequest expected;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(R"""({
    "name"": "my-key",
    "digest": {
      "sha384": "my384digest",
    }
  })""", &expected));

  EXPECT_THAT(actual, IsProtoEqual(expected));
}

TEST(GrpcClientTest, AsymmetricSignRequestWithSha512DigestToProto) {
  Digest digest(DigestType::kSha512, "my512digest");
  AsymmetricSignRequest request("my-key", digest);
  auto actual = GrpcClient::ToProto(request);

  google::cloud::kms::v1::AsymmetricSignRequest expected;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(R"""({
    "name"": "my-key",
    "digest": {
      "sha512": "my512digest",
    }
  })""", &expected));

  EXPECT_THAT(actual, IsProtoEqual(expected));
}

TEST(GrpcClientTest, Sha256DigestToProto) {
  Digest digest(DigestType::kSha256, "test-digest");
  auto actual = GrpcClient::ToProto(digest);

  google::cloud::kms::v1::Digest expected;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(R"""({
    "sha256": "test-digest",
  })""", &expected));

  EXPECT_THAT(actual, IsProtoEqual(expected));
}

TEST(GrpcClientTest, Sha384DigestToProto) {
  Digest digest(DigestType::kSha384, "test-digest");
  auto actual = GrpcClient::ToProto(digest);

  google::cloud::kms::v1::Digest expected;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(R"""({
    "sha384": "test-digest",
  })""", &expected));

  EXPECT_THAT(actual, IsProtoEqual(expected));
}

TEST(GrpcClientTest, Sha512DigestToProto) {
  Digest digest(DigestType::kSha512, "test-digest");
  auto actual = GrpcClient::ToProto(digest);

  google::cloud::kms::v1::Digest expected;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(R"""({
    "sha512": "test-digest",
  })""", &expected));

  EXPECT_THAT(actual, IsProtoEqual(expected));
}

TEST(GrpcClientTest, AsymmetricSignResponseFromProto) {
  google::cloud::kms::v1::AsymmetricSignResponse proto_response;
  proto_response.set_signature("test-signature");
  auto actual = GrpcClient::FromProto(proto_response);

  AsymmetricSignResponse expected("test-signature");
  EXPECT_EQ(actual, expected)
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine