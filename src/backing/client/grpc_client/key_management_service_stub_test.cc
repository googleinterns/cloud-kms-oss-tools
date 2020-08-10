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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "src/backing/client/grpc_client/key_management_service_stub.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {
namespace {

TEST(KeyManagementServiceStubTest, CreateDefaultKeyManagementServiceStub) {
  auto credentials = grpc::InsecureChannelCredentials();

  // Just check that the factory method works, since calling the interface
  // methods will launch actual RPC calls.
  (void)CreateKeyManagementServiceStub("", credentials);
}

}  // namespace
}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine
