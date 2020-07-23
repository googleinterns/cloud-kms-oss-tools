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

#ifndef KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_KEY_MANAGEMENT_SERVICE_STUB_H_
#define KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_KEY_MANAGEMENT_SERVICE_STUB_H_

#include <memory>
#include <string>

#include "grpcpp/grpcpp.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "src/backing/status/status.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {

// Lightweight stub layer over the Cloud KMS API to avoid exposing the
// underlying transport stub (gRPC) directly.
//
// Each stub function passes its arguments directly to the corresponding method
// from `google::cloud::kms::v1::KeyManagementService::StubInterface`. It then
// converts the `grpc::Status` returned by the `StubInterface` to an
// engine-native `Status` object, which makes writing mock return values in
// tests easier and also allows the calling code to directly use the
// `KMSENGINE_RETURN_IF_ERROR` macro from `status.h` on the call.
//
// TODO(zesp): This is used in lieu of the `KeyManagementService::StubInterface`
// gRPC-generated interface for testing purposes, as there are various issues
// with how the `cc_grpc_library` Bazel rule interacts with .proto files defined
// in an external repository which prevents us from automatically generating
// gRPC mocks for the `StubInterface` using the `generate_mocks` flag. It would
// be a good idea to try to get the generated mocks working since otherwise
// there is no way to test that the correct `StubInterface` methods are being
// called without making real gRPC calls. See
// https://github.com/googleinterns/cloud-kms-oss-tools/issues/57 for details.
class KeyManagementServiceStub {
 public:
  virtual ~KeyManagementServiceStub() = default;

  // KeyManagementServiceStub is not copyable or moveable.
  KeyManagementServiceStub(const KeyManagementServiceStub&) = delete;
  KeyManagementServiceStub& operator=(const KeyManagementServiceStub&) = delete;

  virtual Status AsymmetricSign(
      grpc::ClientContext *client_context,
      google::cloud::kms::v1::AsymmetricSignRequest const& request,
      google::cloud::kms::v1::AsymmetricSignResponse *response) const = 0;
  virtual Status GetPublicKey(
      grpc::ClientContext *client_context,
      google::cloud::kms::v1::GetPublicKeyRequest const& request,
      google::cloud::kms::v1::PublicKey *response) const = 0;

 protected:
  KeyManagementServiceStub() = default;
};

// Creates a KeyManagementServiceStub initialized with the given ClientOptions.
std::unique_ptr<KeyManagementServiceStub> CreateKeyManagementServiceStub(
    std::string endpoint,
    std::shared_ptr<grpc::ChannelCredentials> credentials);

}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_GRPC_CLIENT_KEY_MANAGEMENT_SERVICE_STUB_H_
