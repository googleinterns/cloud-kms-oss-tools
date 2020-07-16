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

#ifndef KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_CLIENT_CONTEXT_FACTORY_H_
#define KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_CLIENT_CONTEXT_FACTORY_H_

#include <chrono>
#include <memory>

#include "absl/types/optional.h"
#include "grpcpp/grpcpp.h"
#include "src/backing/client/clock.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {

// Factory class for making a `grpc::ClientContext` from a set of
// `GrpcClientOptions`.
//
// Defined separately from `GrpcClient` primarly for testing.
class ClientContextFactory {
 public:
  virtual ~ClientContextFactory() = default;

  // ClientContextFactory is copyable and moveable.
  ClientContextFactory(const ClientContextFactory& other) = default;
  ClientContextFactory& operator=(const ClientContextFactory& other) = default;

  // Instantiates a `grpc::ClientContext` for use in making gRPC calls.
  //
  // This method does not directly return a `grpc::ClientContext` instance
  // since `grpc::ClientContext` is non-movable. (See discussion at
  // https://github.com/grpc/grpc/issues/16680.)
  virtual std::unique_ptr<grpc::ClientContext> MakeContext() = 0;

 protected:
  ClientContextFactory() = default;
};

// Creates a ClientContextFactory.
std::unique_ptr<ClientContextFactory> CreateClientContextFactory(
    absl::optional<std::chrono::nanoseconds> timeout,
    std::shared_ptr<SystemClock> clock);

}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_CLIENT_CONTEXT_FACTORY_H_
