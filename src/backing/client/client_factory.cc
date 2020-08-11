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

#include "src/backing/client/client_factory.h"

#include <chrono>
#include <memory>
#include <utility>

#include "absl/types/optional.h"
#include "absl/memory/memory.h"
#include "grpcpp/grpcpp.h"
#include "src/backing/client/client.h"
#include "src/backing/client/grpc_client/client_context_factory.h"
#include "src/backing/client/grpc_client/grpc_client.h"
#include "src/backing/client/grpc_client/key_management_service_stub.h"

namespace kmsengine {
namespace backing {
namespace {

using ::kmsengine::backing::grpc_client::GrpcClient;

// Default API endpoint for making gRPC requests against.
//
// Should not be prefixed with "https://" to comply with the gRPC library.
constexpr char kDefaultApiEndpoint[] = "cloudkms.googleapis.com";

std::unique_ptr<Client> MakeDefaultClient(
    absl::optional<std::chrono::milliseconds> timeout) {
  auto stub = grpc_client::CreateKeyManagementServiceStub(
      kDefaultApiEndpoint,
      grpc::GoogleDefaultCredentials());
  auto factory = grpc_client::CreateClientContextFactory(
      timeout, std::make_shared<client::SystemClock>());

  return absl::make_unique<GrpcClient>(std::move(stub), std::move(factory));
}

}  // namespace

std::unique_ptr<Client> MakeDefaultClientWithTimeout(
    std::chrono::milliseconds timeout) {
  return MakeDefaultClient(timeout);
}

std::unique_ptr<Client> MakeDefaultClientWithoutTimeout() {
  return MakeDefaultClient(absl::nullopt);
}

}  // namespace backing
}  // namespace kmsengine
