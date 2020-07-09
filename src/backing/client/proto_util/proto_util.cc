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

#include "src/backing/client/proto_util/proto_util.h"

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "grpcpp/grpcpp.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/status/status.h"

namespace kmsengine {
namespace backing {
namespace {

StatusCode MapStatusCode(grpc::StatusCode const& code) {
  switch (code) {
    case grpc::StatusCode::OK:
      return StatusCode::kOk;
    case grpc::StatusCode::CANCELLED:
      return StatusCode::kCancelled;
    case grpc::StatusCode::UNKNOWN:
      return StatusCode::kUnknown;
    case grpc::StatusCode::INVALID_ARGUMENT:
      return StatusCode::kInvalidArgument;
    case grpc::StatusCode::DEADLINE_EXCEEDED:
      return StatusCode::kDeadlineExceeded;
    case grpc::StatusCode::NOT_FOUND:
      return StatusCode::kNotFound;
    case grpc::StatusCode::ALREADY_EXISTS:
      return StatusCode::kAlreadyExists;
    case grpc::StatusCode::PERMISSION_DENIED:
      return StatusCode::kPermissionDenied;
    case grpc::StatusCode::UNAUTHENTICATED:
      return StatusCode::kUnauthenticated;
    case grpc::StatusCode::RESOURCE_EXHAUSTED:
      return StatusCode::kResourceExhausted;
    case grpc::StatusCode::FAILED_PRECONDITION:
      return StatusCode::kFailedPrecondition;
    case grpc::StatusCode::ABORTED:
      return StatusCode::kAborted;
    case grpc::StatusCode::OUT_OF_RANGE:
      return StatusCode::kOutOfRange;
    case grpc::StatusCode::UNIMPLEMENTED:
      return StatusCode::kUnimplemented;
    case grpc::StatusCode::INTERNAL:
      return StatusCode::kInternal;
    case grpc::StatusCode::UNAVAILABLE:
      return StatusCode::kUnavailable;
    case grpc::StatusCode::DATA_LOSS:
      return StatusCode::kDataLoss;
    default:
      return StatusCode::kUnknown;
  }
}

}  // namespace

google::cloud::kms::v1::Digest MakeDigest(DigestCase type,
                                          absl::string_view digest_bytes) {
  google::cloud::kms::v1::Digest proto_digest;
  switch (type) {
    case DigestCase::kSha256:
      proto_digest.set_sha256(digest_bytes.data());
      break;
    case DigestCase::kSha384:
      proto_digest.set_sha384(digest_bytes.data());
      break;
    case DigestCase::kSha512:
      proto_digest.set_sha512(digest_bytes.data());
      break;
  }
  return proto_digest;
}

Status FromRpcErrorToStatus(grpc::Status const& status) {
  return Status(MapStatusCode(status.error_code()),
                std::move(status.error_message()));
}

}  // namespace backing
}  // namespace kmsengine
