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

#ifndef KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_CONTEXT_FACTORY_H_
#define KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_CONTEXT_FACTORY_H_

#include <chrono>
#include <memory>

#include <grpcpp/grpcpp.h>

#include "src/backing/client/clock.h"
#include "src/backing/client/grpc_client_options.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace grpc_client_impl {

// Factory class for making a `grpc::ClientContext` from a set of
// `GrpcClientOptions`.
//
// Defined separately from `GrpcClient` primarly for testing.
class GrpcClientContextFactory {
 public:
  GrpcClientContextFactory(std::shared_ptr<GrpcClientOptions> options,
                           std::shared_ptr<SystemClock> clock)
      : client_options_(options), clock_(clock) {}

  // Instantiates a `grpc::ClientContext` for use in making gRPC calls based on
  // settings from the `GrpcClientOptions` with this `GrpcClient`.
  //
  // This method does not directly return a `grpc::ClientContext` instance
  // since `grpc::ClientContext` is non-movable. (See related discussion at
  // https://github.com/grpc/grpc/issues/16680.)
  std::unique_ptr<grpc::ClientContext> MakeContext();

 private:
  std::shared_ptr<GrpcClientOptions> client_options_;
  std::shared_ptr<SystemClock> clock_;
};

}  // namespace grpc_client_impl
}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_CONTEXT_FACTORY_H_
