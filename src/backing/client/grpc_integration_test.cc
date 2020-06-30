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

#include <cstdlib>

#include <gtest/gtest.h>
#include <google/protobuf/text_format.h>

#include "absl/types/optional.h"
#include "src/backing/client/grpc_client.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

std::string GetEnv(char const* variable) {
  char *buffer = std::getenv(variable);
  if (buffer == nullptr) {
    return "";
  }
  return std::string(buffer);
}

class GrpcIntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    crypto_key_version_ = GetEnv("TEST_CRYPTO_KEY_VERSION");
    ASSERT_FALSE(crypto_key_version_.empty()) <<
        "TEST_CRYPTO_KEY_VERSION is not set";
  }

  std::string crypto_key_version() const { return crypto_key_version_; }

 private:
  std::string crypto_key_version_;
};

TEST_F(GrpcIntegrationTest, AsymmetricSign) {
  // The default `GrpcClientOptions` constructor builds gRPC credentials via
  // `grpc::GoogleDefaultCredentials()`.
  GrpcClientOptions options;
  GrpcClient client(options);

  // SHA-256 hash for "hello world".
  Digest digest(
      DigestType::kSha256,
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
  AsymmetricSignRequest request(crypto_key_version(), digest);

  auto response = client.AsymmetricSign(request);
  EXPECT_TRUE(response.ok());
  EXPECT_FALSE(response.value().signature().empty());
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
