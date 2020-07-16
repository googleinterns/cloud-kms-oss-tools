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

#ifndef KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_GRPC_CLIENT_H_
#define KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_GRPC_CLIENT_H_

#include <string>
#include <memory>

#include "src/backing/client/client.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/grpc_client/key_management_service_stub.h"
#include "src/backing/client/grpc_client/client_context_factory.h"
#include "src/backing/client/public_key.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {

// `Client` implementation for the Cloud KMS API with gRPC as the transport
// medium.
class GrpcClient : public Client {
 public:
  GrpcClient(std::unique_ptr<KeyManagementServiceStub> stub,
             std::unique_ptr<ClientContextFactory> client_context_factory)
      : stub_(std::move(stub)),
        client_context_factory_(std::move(client_context_factory)) {}
  ~GrpcClient() override = default;

  // GrpcClient is move-only.
  GrpcClient(GrpcClient&& other);
  GrpcClient& operator=(GrpcClient&& other);

  // `Client` interface methods.
  StatusOr<std::string> AsymmetricSign(
      std::string key_version_resource_id, DigestCase digest_case,
      std::string digest_bytes) override;
  StatusOr<std::unique_ptr<PublicKey>> GetPublicKey(
      std::string key_version_resource_id) override;

 private:
  std::unique_ptr<KeyManagementServiceStub> stub_;
  std::unique_ptr<ClientContextFactory> client_context_factory_;
};

}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_GRPC_CLIENT_H_
