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

#include "src/backing/client/grpc_client/client_context_factory.h"

#include <chrono>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/types/optional.h"
#include "grpcpp/grpcpp.h"
#include "src/backing/client/clock.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {
namespace {

// Factory class for making a `grpc::ClientContext` from a set of
// `GrpcClientOptions`.
//
// Defined separately from `GrpcClient` primarly for testing.
class GrpcClientContextFactory : public ClientContextFactory {
 public:
  // While the underlying `timeout` is stored as `std::chrono::nanoseconds`,
  // the setter will accept and implicitly convert any type of
  // `std::chrono::duration`. We use nanoseconds here to allow for as much
  // precision as possible.
  //
  // If timeout == `absl::nullopt`, then no deadline will be set when making
  // requests. This means RPC calls will always take as long as the server is
  // still processing the call, which means RPC calls may take theoretically
  // unbounded time. However, gRPC's "keepalive" mechanism will automatically
  // terminate requests early if the API endpoint is unavailable or the network
  // connection is dropped, which makes `absl::nullopt` a reasonable setting for
  // clients to set.
  GrpcClientContextFactory(absl::optional<std::chrono::nanoseconds> timeout,
                           std::shared_ptr<SystemClock> clock)
      : timeout_duration_(timeout), clock_(std::move(clock)) {}

  // Instantiates a `grpc::ClientContext` for use in making gRPC calls based on
  // settings from the `GrpcClientOptions` with this `GrpcClient`.
  //
  // This method does not directly return a `grpc::ClientContext` instance
  // since `grpc::ClientContext` is non-movable. (See related discussion at
  // https://github.com/grpc/grpc/issues/16680.)
  std::unique_ptr<grpc::ClientContext> MakeContext() override {
    auto context = absl::make_unique<grpc::ClientContext>();
    if (timeout_duration_.has_value()) {
      auto deadline = clock_->Now() + timeout_duration_.value();
      context->set_deadline(deadline);
    }
    return context;
  }

 private:
  absl::optional<std::chrono::nanoseconds> timeout_duration_;
  std::shared_ptr<SystemClock> clock_;
};

}  // namespace

std::unique_ptr<ClientContextFactory> CreateClientContextFactory(
    absl::optional<std::chrono::nanoseconds> timeout,
    std::shared_ptr<SystemClock> clock) {
  return absl::make_unique<GrpcClientContextFactory>(timeout, std::move(clock));
}

}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine
