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

#ifndef KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_H_
#define KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_H_

#include <memory>

#include <google/cloud/kms/v1/service.grpc.pb.h>
#include <google/cloud/kms/v1/service.pb.h>

#include "src/backing/client/asymmetric_sign_request.h"
#include "src/backing/client/asymmetric_sign_response.h"
#include "src/backing/client/client.h"
#include "src/backing/client/clock.h"
#include "src/backing/client/digest.h"
#include "src/backing/client/grpc_client_impl/grpc_client_context_factory.h"
#include "src/backing/client/grpc_client_options.h"
#include "src/backing/status/status.h"

namespace kmsengine {
namespace backing {
namespace client {

class GrpcClient : Client {
 public:
  explicit GrpcClient(
      std::shared_ptr<GrpcClientOptions> options,
      std::shared_ptr<SystemClock> clock = std::make_shared<SystemClock>());
  ~GrpcClient() override = default;

  // GrpcClient is copyable and movable.
  GrpcClient(const GrpcClient& other) = default;
  GrpcClient& operator=(const GrpcClient& other) = default;

  // Overriden methods from the ApiClient interface.
  StatusOr<AsymmetricSignResponse> AsymmetricSign(
      AsymmetricSignRequest const& request) override;

  // Converts from the native representation of an API request to the gRPC
  // protobuf representation.
  static google::cloud::kms::v1::AsymmetricSignRequest ToProto(
      AsymmetricSignRequest request);
  static google::cloud::kms::v1::Digest ToProto(Digest digest);

  // Converts from the gRPC protobuf representation of an API request to the
  // native representation.
  static AsymmetricSignResponse FromProto(
      google::cloud::kms::v1::AsymmetricSignResponse proto_response);

 private:
  // gRPC stub for making `google.cloud.kms.v1` gRPC calls.
  std::shared_ptr<
      google::cloud::kms::v1::KeyManagementService::StubInterface> stub_;

  std::shared_ptr<GrpcClientOptions> client_options_;
  grpc_client_impl::GrpcClientContextFactory client_context_factory_;
};

}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_H_
