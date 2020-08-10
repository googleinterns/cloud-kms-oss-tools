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

#include "src/backing/client/grpc_client/key_management_service_stub.h"

#include <chrono>
#include <memory>

#include "absl/memory/memory.h"
#include "google/cloud/kms/v1/resources.grpc.pb.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "grpcpp/grpcpp.h"
#include "src/backing/status/status.h"
#include "src/backing/client/grpc_client/proto_util.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {
namespace {

namespace kms_proto = ::google::cloud::kms::v1;

// Stub that calls the Cloud KMS API gRPC interface.
class GrpcKeyManagementServiceStub : public KeyManagementServiceStub {
 public:
  explicit GrpcKeyManagementServiceStub(
      std::unique_ptr<kms_proto::KeyManagementService::StubInterface> stub)
      : grpc_stub_(std::move(stub)) {}

  // KeyManagementServiceStub interface methods.
  Status AsymmetricSign(
      grpc::ClientContext *client_context,
      kms_proto::AsymmetricSignRequest const& request,
      kms_proto::AsymmetricSignResponse *response) const override {
    return FromGrpcStatusToStatus(
        grpc_stub_->AsymmetricSign(client_context, request, response));
  }

  Status GetPublicKey(
      grpc::ClientContext *client_context,
      kms_proto::GetPublicKeyRequest const& request,
      kms_proto::PublicKey *response) const override {
    return FromGrpcStatusToStatus(
        grpc_stub_->GetPublicKey(client_context, request, response));
  }

 private:
  std::unique_ptr<kms_proto::KeyManagementService::StubInterface> grpc_stub_;
};

}  // namespace

std::unique_ptr<KeyManagementServiceStub> CreateKeyManagementServiceStub(
    std::string endpoint,
    std::shared_ptr<grpc::ChannelCredentials> credentials) {
  auto channel = grpc::CreateChannel(endpoint, credentials);
  auto grpc_stub = kms_proto::KeyManagementService::NewStub(channel);
  return absl::make_unique<GrpcKeyManagementServiceStub>(std::move(grpc_stub));
}

}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine
