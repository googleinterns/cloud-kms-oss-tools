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

#include "src/backing/client/grpc_client.h"

#include <chrono>
#include <memory>
#include <string>
#include <utility>

#include <crc32c/crc32c.h>
#include <google/cloud/grpc_error_delegate.h>
#include <google/cloud/kms/v1/resources.grpc.pb.h>
#include <google/cloud/kms/v1/resources.pb.h>
#include <google/cloud/kms/v1/service.grpc.pb.h>
#include <google/cloud/kms/v1/service.pb.h>
#include <grpcpp/grpcpp.h>

#include "absl/types/optional.h"
#include "google/cloud/status_or.h"
#include "src/backing/client/client.h"
#include "src/backing/client/asymmetric_sign_request.h"
#include "src/backing/client/asymmetric_sign_response.h"
#include "src/backing/client/grpc_client_options.h"
#include "src/backing/client/digest.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

// Helper function for creating a `KeyManagementService::Stub` in the
// GrpcClient's constructor initializer list.
std::shared_ptr<google::cloud::kms::v1::KeyManagementService::Stub>
    CreateStub(GrpcClientOptions const& options) {
  auto channel = grpc::CreateChannel(options.GetEndpoint(),
                                     options.GetCredentials());
  return google::cloud::kms::v1::KeyManagementService::NewStub(channel);
}

}  // namespace

GrpcClient::GrpcClient(GrpcClientOptions const& options)
    : stub_(CreateStub(options)), client_options_(options) {
}

grpc::ClientContext GrpcClient::MakeClientContext() {
  grpc::ClientContext context;

  // Set optional deadline. If no timeout is set, then RPC calls will always
  // take as long as the server is still processing the call (if the
  // connection drops, the RPC will end due to gRPC's `keepalive` mechanism).
  absl::optional<auto> duration = client_options_.GetTimeoutDuration();
  if (duration.has_value()) {
    auto deadline = std::chrono::system_clock::now() + duration.value();
    context.set_deadline(deadline);
  }

  return context;
}

StatusOr<AsymmetricSignResponse> GrpcClient::AsymmetricSign(
    AsymmetricSignRequest const& request) {
  grpc::ClientContext context = MakeClientContext();
  auto proto_request = ToProto(request);
  google::cloud::kms::v1::AsymmetricSignResponse response;

  auto status = stub_->AsymmetricSign(&context, proto_request, &response);
  if (!status.ok()) {
    return google::cloud::MakeStatusFromRpcError(status);
  }

  return FromProto(std::move(response));
}

google::cloud::kms::v1::AsymmetricSignRequest GrpcClient::ToProto(
    AsymmetricSignRequest request) {
  google::cloud::kms::v1::AsymmetricSignRequest proto_request;
  proto_request.set_name(std::move(request.KeyName()));
  proto_request.set_allocated_digest(std::move(ToProto(request.Digest())));
  return proto_request;
}

google::cloud::kms::v1::Digest GrpcClient::ToProto(Digest digest) {
  google::cloud::kms::v1::Digest proto_digest;
  auto bytes = std::move(digest.Bytes());
  switch (digest.Type()) {
    case kSha256:
      proto_digest.set_sha256(bytes);
      break;
    case kSha384:
      proto_digest.set_sha384(bytes);
      break;
    case kSha512:
      proto_digest.set_sha512(bytes);
      break;
  }
  return proto_digest;
}

AsymmetricSignResponse GrpcClient::FromProto(
    google::cloud::kms::v1::AsymmetricSignResponse proto_response) {
  return AsymmetricSignResponse(proto_response.signature());
}

// std::string GrpcClient::Crc32cFromProto(
//     google::protobuf::UInt32Value const& v) {
//   auto endian_encoded = google::cloud::internal::EncodeBigEndian(v.value());
//   return Base64Encode(endian_encoded);
// }

// std::uint32_t GrpcClient::Crc32cToProto(std::string const& v) {
//   auto decoded = Base64Decode(v);
//   return google::cloud::internal::DecodeBigEndian<std::uint32_t>(
//              std::string(decoded.begin(), decoded.end()))
//       .value();
// }

// std::string GrpcClient::MD5FromProto(std::string const& v) {
//   if (v.empty()) return {};
//   auto binary = internal::HexDecode(v);
//   return internal::Base64Encode(binary);
// }

// std::string GrpcClient::MD5ToProto(std::string const& v) {
//   if (v.empty()) return {};
//   auto binary = internal::Base64Decode(v);
//   return internal::HexEncode(binary);
// }

}  // namespace client
}  // namespace backing
}  // namespace kmsengine
