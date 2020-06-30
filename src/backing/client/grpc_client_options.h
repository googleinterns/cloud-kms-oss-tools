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

#ifndef KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_OPTIONS_H_
#define KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_OPTIONS_H_

#include <chrono>
#include <string>

#include <grpcpp/grpcpp.h>

#include "absl/types/optional.h"

namespace kmsengine {
namespace backing {
namespace client {

// Describes the configuration for a `client::GrpcClient` object.
class GrpcClientOptions {
 public:
  // Constructs a GrpcClientOptions instance with default options specified in
  // grpc_client_default_options.h.
  //
  // The zero-arity constructor uses the Application Default Credentials (ADC)
  // strategy for retrieving credentials. For more details on ADC, see
  // https://cloud.google.com/docs/authentication/production.
  //
  // The constructor for explicitly specifiying `grpc::ChannelCredentials` is
  // exposed primarily for testing purposes. The OpenSSL bridge layer should
  // use the zero-arity constructor since it does not have access to symbols
  // in the `grpc` namespace.
  explicit GrpcClientOptions();
  explicit GrpcClientOptions(
      std::shared_ptr<grpc::ChannelCredentials> credentials);

  // GrpcClientOptions is copyable and movable.
  GrpcClientOptions(const GrpcClientOptions& other) = default;
  GrpcClientOptions& operator=(const GrpcClientOptions& other) = default;

  // Getter and setter for the `grpc::ChannelCredentials` used when making
  // requests with a `GrpcClient`.
  std::shared_ptr<grpc::ChannelCredentials> credentials() const;
  void set_credentials(std::shared_ptr<grpc::ChannelCredentials> credentials);

  // Getter and setter for the timeout duration used to set deadlines when
  // making gRPC requests.
  //
  // While the underlying time duration is stored as `std::chrono::nanoseconds`,
  // the setter will accept and implicitly convert any type of
  // `std::chrono::duration`.
  //
  // If timeout = nullopt, then no deadline will be set when making requests.
  // This means RPC calls will always take as long as the server is still
  // processing the call, which means RPC calls may take theoretically
  // unbounded time. (However, gRPC's "keepalive" mechanism will automatically
  // terminate requests early if the API endpoint is unavailable or the network
  // connection is dropped.)
  absl::optional<std::chrono::nanoseconds> timeout_duration() const;
  void set_timeout_duration(absl::optional<std::chrono::nanoseconds> duration);

  // Getter and setter for the HTTP endpoint where API requests are sent.
  std::string const& api_endpoint() const;
  void set_api_endpoint(std::string endpoint);

 private:
  std::shared_ptr<grpc::ChannelCredentials> credentials_;
  absl::optional<std::chrono::nanoseconds> timeout_duration_;
  std::string api_endpoint_;
};

}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_OPTIONS_H_
