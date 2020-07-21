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

#include "src/backing/client/grpc_client/grpc_client.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/client/grpc_client/key_management_service_stub.h"
#include "src/backing/client/grpc_client/client_context_factory.h"
#include "src/backing/client/grpc_client/proto_util.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {

StatusOr<std::string> GrpcClient::AsymmetricSign(
    std::string key_version_resource_id,
    DigestCase digest_case,
    std::string digest_bytes) {
  google::cloud::kms::v1::AsymmetricSignRequest proto_request;
  proto_request.set_name(std::move(key_version_resource_id));
  proto_request.mutable_digest()->CopyFrom(
      MakeDigest(digest_case, digest_bytes));

  auto context = client_context_factory_->MakeContext();
  google::cloud::kms::v1::AsymmetricSignResponse proto_response;
  KMSENGINE_RETURN_IF_ERROR(stub_->AsymmetricSign(context.get(), proto_request,
                                                  &proto_response));

  return std::move(proto_response.signature());
}

StatusOr<PublicKey> GrpcClient::GetPublicKey(
    std::string key_version_resource_id) {
  google::cloud::kms::v1::GetPublicKeyRequest proto_request;
  proto_request.set_name(std::move(key_version_resource_id));

  auto context = client_context_factory_->MakeContext();
  google::cloud::kms::v1::PublicKey proto_response;
  KMSENGINE_RETURN_IF_ERROR(stub_->GetPublicKey(context.get(), proto_request,
                                                &proto_response));

  return PublicKey(
      proto_response.pem(),
      FromProtoToCryptoKeyVersionAlgorithm(proto_response.algorithm()));
}

}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine
