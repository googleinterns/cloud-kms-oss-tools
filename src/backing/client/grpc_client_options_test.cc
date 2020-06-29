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

#include <chrono>
#include <optional>
#include <string>

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

#include "src/backing/client/grpc_client_options.h"
#include "src/backing/client/grpc_client_default_options.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

TEST(GrpcClientOptionsTest, CredentialsRoundtrip) {
  // In the CI environment grpc::GoogleDefaultCredentials() may assert. Use the
  // insecure credentials to initialize the options in any unit test.
  auto expected = grpc::InsecureChannelCredentials();
  GrpcClientOptions options(expected);
  EXPECT_EQ(options.GetCredentials(), expected);

  auto other_credentials = grpc::InsecureChannelCredentials();
  EXPECT_NE(options.GetCredentials(), other_credentials);
  options.SetCredentials(other_credentials);
  EXPECT_EQ(options.GetCredentials(), other_credentials);
}

TEST(GrpcClientOptionsTest, TimeoutDurationRoundtrip) {
  // Use unauthenticated credentials for testing.
  GrpcClientOptions options(grpc::InsecureChannelCredentials());

  // Check default was initially set.
  EXPECT_EQ(options.GetTimeoutDuration(), kDefaultTimeoutDuration);

  options.SetTimeoutDuration(std::chrono::milliseconds(100));
  EXPECT_EQ(options.GetTimeoutDuration(), std::chrono::milliseconds(100));

  options.SetTimeoutDuration(std::chrono::seconds(5));
  EXPECT_EQ(options.GetTimeoutDuration(), std::chrono::seconds(5));

  options.SetTimeoutDuration(absl::nullopt);
  EXPECT_EQ(options.GetTimeoutDuration(), absl::nullopt);
}

TEST(GrpcClientOptionsTest, ApiEndpointRoundtrip) {
  // Use unauthenticated credentials for testing.
  GrpcClientOptions options(grpc::InsecureChannelCredentials());

  // Check default was initially set.
  EXPECT_EQ(options.GetApiEndpoint(), kDefaultApiEndpoint);

  options.SetApiEndpoint("https://example.com");
  EXPECT_EQ(options.GetApiEndpoint(), "https://example.com");

  options.SetApiEndpoint("invalid_endpoint");
  EXPECT_EQ(options.GetApiEndpoint(), "invalid_endpoint");
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
