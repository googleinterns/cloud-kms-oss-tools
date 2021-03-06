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
 */

#include <string>
#include <tuple>

#include <gmock/gmock.h>

#include "absl/strings/str_cat.h"
#include "absl/strings/escaping.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/grpc_client/proto_util.h"
#include "src/backing/status/status.h"

namespace kmsengine {
namespace backing {
namespace {

using ::testing::Combine;
using ::testing::StrEq;
using ::testing::Values;
using ::testing::ValuesIn;

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

// Sample digests for testing purposes.
const std::string kSampleDigests[] = {
  // Example SHA-256 digest of "hello world" for testing.
  absl::HexStringToBytes(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
  // Check that signing operations handle digests containing null bytes.
  absl::HexStringToBytes(
      "ababab0000000000000000000000000000000000000000000000000000bababa"),
  // Ends with null bytes.
  absl::HexStringToBytes(
      "bababa0000000000000000000000000000000000000000000000000000000000"),
  // Starts with null bytes and ends with non-null bytes.
  absl::HexStringToBytes(
      "0000000000000000000000000000000000000000000000000000000000ababab"),
  // Check all null string.
  absl::HexStringToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000"),
  // Check arbitrary string.
  "an arbitrary digest",
  // Check empty string.
  "",
};

class MakeDigestTest : public
    testing::TestWithParam<std::tuple<DigestCase, std::string>> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(
    DigestParameters, MakeDigestTest,
    Combine(Values(DigestCase::kSha256,
                   DigestCase::kSha384,
                   DigestCase::kSha512),
            ValuesIn(kSampleDigests)));

TEST_P(MakeDigestTest, MakeDigest) {
  auto expected_digest_type = std::get<0>(GetParam());
  auto expected_digest_bytes = std::get<1>(GetParam());

  auto actual = MakeDigest(expected_digest_type, expected_digest_bytes);
  EXPECT_EQ(FromProtoToDigestCase(actual.digest_case()), expected_digest_type);
  EXPECT_THAT(GetDigestBytes(actual), StrEq(expected_digest_bytes));
}

// Mapping between `StatusCode` cases and their protobuf equivalents.
struct CorrespondingStatusCode {
  grpc::StatusCode proto;
  StatusCode code;
};

constexpr CorrespondingStatusCode kStatusCodeMapping[] = {
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

class FromGrpcStatusToStatusTest : public
    testing::TestWithParam<CorrespondingStatusCode> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(StatusCodeParameters, FromGrpcStatusToStatusTest,
                         ValuesIn(kStatusCodeMapping));

TEST_P(FromGrpcStatusToStatusTest, ConversionsWork) {
  auto mapping = GetParam();
  std::string const message = "test message";
  auto const original = grpc::Status(mapping.proto, message);
  auto const expected = Status(mapping.code, message);
  auto const actual = FromGrpcStatusToStatus(original);
  EXPECT_EQ(expected, actual);
}

using ProtoDigestCase = google::cloud::kms::v1::Digest::DigestCase;

// Mapping between `DigestCase` cases and their protobuf equivalents.
struct CorrespondingDigestCase {
  DigestCase expected;
  ProtoDigestCase proto;
};

constexpr CorrespondingDigestCase kDigestMapping[] = {
  {DigestCase::kSha256, ProtoDigestCase::kSha256},
  {DigestCase::kSha384, ProtoDigestCase::kSha384},
  {DigestCase::kSha512, ProtoDigestCase::kSha512},
};

class FromProtoToDigestCaseTest : public
    testing::TestWithParam<CorrespondingDigestCase> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(DigestCaseParameters, FromProtoToDigestCaseTest,
                         ValuesIn(kDigestMapping));

TEST_P(FromProtoToDigestCaseTest, ConversionsWork) {
  auto mapping = GetParam();
  EXPECT_EQ(mapping.expected, FromProtoToDigestCase(mapping.proto));
}

using ProtoCryptoKeyVersion = google::cloud::kms::v1::CryptoKeyVersion;

// Mapping between `CryptoKeyVersionAlgorithm` cases and their protobuf
// equivalents.
struct CorrespondingCryptoKeyVersionAlgorithm {
  CryptoKeyVersionAlgorithm expected;
  google::cloud::kms::v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm proto;
};

constexpr CorrespondingCryptoKeyVersionAlgorithm kCryptoAlgorithmMapping[] = {
  {CryptoKeyVersionAlgorithm::kAlgorithmUnspecified,
      ProtoCryptoKeyVersion::CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED},
  {CryptoKeyVersionAlgorithm::kGoogleSymmetricEncryption,
      ProtoCryptoKeyVersion::GOOGLE_SYMMETRIC_ENCRYPTION},
  {CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256,
      ProtoCryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaSignPss3072Sha256,
      ProtoCryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha256,
      ProtoCryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha512,
      ProtoCryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512},
  {CryptoKeyVersionAlgorithm::kRsaSignPkcs2048Sha256,
      ProtoCryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaSignPkcs3072Sha256,
      ProtoCryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha256,
      ProtoCryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha512,
      ProtoCryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512},
  {CryptoKeyVersionAlgorithm::kRsaDecryptOaep2048Sha256,
      ProtoCryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaDecryptOaep3072Sha256,
      ProtoCryptoKeyVersion::RSA_DECRYPT_OAEP_3072_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha256,
      ProtoCryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256},
  {CryptoKeyVersionAlgorithm::kRsaDecryptOaep4096Sha512,
      ProtoCryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA512},
  {CryptoKeyVersionAlgorithm::kEcSignP256Sha256,
      ProtoCryptoKeyVersion::EC_SIGN_P256_SHA256},
  {CryptoKeyVersionAlgorithm::kEcSignP384Sha384,
      ProtoCryptoKeyVersion::EC_SIGN_P384_SHA384},
  {CryptoKeyVersionAlgorithm::kExternalSymmetricEncryption,
      ProtoCryptoKeyVersion::EXTERNAL_SYMMETRIC_ENCRYPTION},
};

class FromProtoToCryptoKeyVersionAlgorithmTest : public
    testing::TestWithParam<CorrespondingCryptoKeyVersionAlgorithm> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(CryptoKeyVersionAlgorithmParameters,
                         FromProtoToCryptoKeyVersionAlgorithmTest,
                         ValuesIn(kCryptoAlgorithmMapping));

TEST_P(FromProtoToCryptoKeyVersionAlgorithmTest, ConversionsWork) {
  auto mapping = GetParam();
  EXPECT_EQ(mapping.expected,
            FromProtoToCryptoKeyVersionAlgorithm(mapping.proto));
}

}  // namespace
}  // namespace backing
}  // namespace kmsengine
