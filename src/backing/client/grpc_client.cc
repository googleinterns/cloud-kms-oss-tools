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

#include <google/cloud/kms/v1/resources.grpc.pb.h>
#include <google/cloud/kms/v1/resources.pb.h>
#include <google/cloud/kms/v1/service.grpc.pb.h>
#include <google/cloud/kms/v1/service.pb.h>
#include <grpcpp/grpcpp.h>

#include "absl/types/optional.h"
#include "src/backing/client/client.h"
#include "src/backing/client/asymmetric_sign_request.h"
#include "src/backing/client/asymmetric_sign_response.h"
#include "src/backing/client/grpc_client_options.h"
#include "src/backing/client/digest.h"
#include "src/backing/status/status.h"
#include "google/cloud/grpc_error_delegate.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

// Helper function for creating a `KeyManagementService::Stub` in the
// GrpcClient's constructor initializer list.
std::shared_ptr<google::cloud::kms::v1::KeyManagementService::Stub>
    CreateStub(GrpcClientOptions const& options) {
  auto channel = grpc::CreateChannel(options.api_endpoint(),
                                     options.credentials());
  return google::cloud::kms::v1::KeyManagementService::NewStub(channel);
}

}  // namespace

GrpcClient::GrpcClient(GrpcClientOptions const& options)
    : stub_(CreateStub(options)), client_options_(options) {
}

// Instantiates a `grpc::ClientContext` for use in making gRPC calls based on
// settings from the `GrpcClientOptions` with this `GrpcClient`.
//
// This macro should only be used within instance methods (not statics).
//
// Needs to be a macro since grpc::ClientContext is non-movable. See
// https://github.com/grpc/grpc/issues/16680 for context.
//
// The do-while serves to keep intermediary variables within scope of the macro.
#define KMSENGINE_MAKE_CLIENT_CONTEXT(__context_name)                      \
  grpc::ClientContext __context_name;                                      \
  do {                                                                     \
    auto duration = this->client_options_.timeout_duration();              \
    if (duration.has_value()) {                                            \
      auto deadline = std::chrono::system_clock::now() + duration.value(); \
      __context_name.set_deadline(deadline);                               \
    }                                                                      \
  } while (false)

StatusOr<AsymmetricSignResponse> GrpcClient::AsymmetricSign(
    AsymmetricSignRequest const& request) {
  KMSENGINE_MAKE_CLIENT_CONTEXT(context);
  auto proto_request = ToProto(request);
  google::cloud::kms::v1::AsymmetricSignResponse response;

  auto status = stub_->AsymmetricSign(&context, proto_request, &response);
  if (!status.ok()) {
    return google::cloud::MakeStatusFromRpcError(status);
  }

  return FromProto(std::move(response));
}

#undef KMSENGINE_MAKE_CLIENT_CONTEXT

google::cloud::kms::v1::AsymmetricSignRequest GrpcClient::ToProto(
    AsymmetricSignRequest request) {
  google::cloud::kms::v1::AsymmetricSignRequest proto_request;
  proto_request.set_name(std::move(request.key_name()));

  google::cloud::kms::v1::Digest *proto_digest = proto_request.mutable_digest();
  proto_digest->CopyFrom(ToProto(request.digest()));
  return proto_request;
}

google::cloud::kms::v1::Digest GrpcClient::ToProto(Digest digest) {
  google::cloud::kms::v1::Digest proto_digest;
  auto bytes = std::move(digest.bytes());
  switch (digest.type()) {
    case DigestType::kSha256:
      proto_digest.set_sha256(bytes);
      break;
    case DigestType::kSha384:
      proto_digest.set_sha384(bytes);
      break;
    case DigestType::kSha512:
      proto_digest.set_sha512(bytes);
      break;
  }
  return proto_digest;
}

AsymmetricSignResponse GrpcClient::FromProto(
    google::cloud::kms::v1::AsymmetricSignResponse proto_response) {
  return AsymmetricSignResponse(proto_response.signature());
}

}  // namespace client
}  // namespace backing
}  // namespace kmsengine
