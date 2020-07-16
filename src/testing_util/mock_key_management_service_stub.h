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

#ifndef KMSENGINE_TESTING_UTIL_MOCK_KEY_MANAGEMENT_SERVICE_STUB_H_
#define KMSENGINE_TESTING_UTIL_MOCK_KEY_MANAGEMENT_SERVICE_STUB_H_

#include <memory>

#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "grpcpp/grpcpp.h"
#include "src/backing/status/status.h"
#include "src/backing/client/grpc_client/key_management_service_stub.h"

namespace kmsengine {
namespace testing_util {

class MockKeyManagementServiceStub :
    public ::kmsengine::backing::grpc_client::KeyManagementServiceStub {
 public:
  MOCK_METHOD(Status, AsymmetricSign,
      (grpc::ClientContext *client_context,
       google::cloud::kms::v1::AsymmetricSignRequest const& request,
       google::cloud::kms::v1::AsymmetricSignResponse *response),
      (override));
  MOCK_METHOD(Status, GetPublicKey,
      (grpc::ClientContext *client_context,
       google::cloud::kms::v1::GetPublicKeyRequest const& request,
       google::cloud::kms::v1::PublicKey *response),
      (override));
};

}  // namespace testing_util
}  // namespace kmsengine

#endif  // KMSENGINE_TESTING_UTIL_MOCK_KEY_MANAGEMENT_SERVICE_STUB_H_
