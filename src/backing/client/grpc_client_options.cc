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

#include "src/backing/client/grpc_client_options.h"

#include <chrono>
#include <string>
#include <utility>

#include <grpcpp/grpcpp.h>

#include "absl/types/optional.h"
#include "src/backing/client/grpc_client_default_options.h"

namespace kmsengine {
namespace backing {
namespace client {

GrpcClientOptions::GrpcClientOptions()
    : GrpcClientOptions(grpc::GoogleDefaultCredentials()) {
}

GrpcClientOptions::GrpcClientOptions(
    std::shared_ptr<grpc::ChannelCredentials> credentials)
    : credentials_(std::move(credentials)),
      timeout_duration_(kDefaultTimeoutDuration),
      api_endpoint_(kDefaultApiEndpoint) {
}

std::shared_ptr<grpc::ChannelCredentials>
    GrpcClientOptions::credentials() const {
  return credentials_;
}

void GrpcClientOptions::set_credentials(
    std::shared_ptr<grpc::ChannelCredentials> credentials) {
  credentials_ = std::move(credentials);
}

absl::optional<std::chrono::nanoseconds>
    GrpcClientOptions::timeout_duration() const {
  return timeout_duration_;
}

void GrpcClientOptions::set_timeout_duration(
    absl::optional<std::chrono::nanoseconds> duration) {
  timeout_duration_ = duration;
}

std::string const& GrpcClientOptions::api_endpoint() const {
  return api_endpoint_;
}

void GrpcClientOptions::set_api_endpoint(std::string endpoint) {
  api_endpoint_ = std::move(endpoint);
}

}  // namespace client
}  // namespace backing
}  // namespace kmsengine
