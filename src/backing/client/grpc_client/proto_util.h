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

#ifndef KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_PROTO_UTIL_H_
#define KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_PROTO_UTIL_H_

#include <string>

#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "grpcpp/grpcpp.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/crypto_key_version_algorithm.h"
#include "src/backing/status/status.h"

namespace kmsengine {
namespace backing {

// Factory function which creates an protobuf `Digest`.
google::cloud::kms::v1::Digest MakeDigest(DigestCase type,
                                          absl::string_view digest_bytes);

// Helper function for converting a `grpc::Status` to a engine-native `Status`.
Status FromGrpcStatusToStatus(grpc::Status const& status);

// Helper function for converting `Digest::DigestCase` protobuf enums to
// engine-native `DigestCase` enums.
constexpr DigestCase FromProtoToDigestCase(
    google::cloud::kms::v1::Digest::DigestCase
        algorithm) {
  // Works because underlying values of engine-native `DigestCase` enums are
  // equivalent to their protobuf counterparts.
  return static_cast<DigestCase>(algorithm);
}

// Helper function for converting `CryptoKeyVersion_CryptoKeyVersionAlgorithm`
// protobuf enums to engine-native `CryptoKeyVersionAlgorithm` enums.
constexpr CryptoKeyVersionAlgorithm FromProtoToCryptoKeyVersionAlgorithm(
    google::cloud::kms::v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm
        algorithm) {
  // Works because underlying values of engine-native
  // `CryptoKeyVersionAlgorithm` enums are equivalent to their protobuf
  // counterparts.
  return static_cast<CryptoKeyVersionAlgorithm>(algorithm);
}

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_PROTO_UTIL_H_
