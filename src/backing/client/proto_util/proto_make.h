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

#ifndef KMSENGINE_BACKING_CLIENT_PROTO_UTIL_PROTO_MAKE_H_
#define KMSENGINE_BACKING_CLIENT_PROTO_UTIL_PROTO_MAKE_H_

#include <string>

#include <google/cloud/kms/v1/resources.grpc.pb.h>
#include <google/cloud/kms/v1/resources.pb.h>
#include <google/cloud/kms/v1/service.grpc.pb.h>
#include <google/cloud/kms/v1/service.pb.h>

namespace kmsengine {
namespace backing {
namespace proto_util {

// Factory function which creates an protobuf `AsymmetricSignRequest`.
google::cloud::kms::v1::AsymmetricSignRequest MakeAsymmetricSignRequest(
    std::string key_version_resource_id,
    google::cloud::kms::v1::Digest digest);

// Factory function which creates an protobuf `GetPublicKeyRequest`.
google::cloud::kms::v1::GetPublicKeyRequest MakeGetPublicKeyRequest(
    std::string key_version_resource_id);

// Factory function which creates an protobuf `Digest`.
google::cloud::kms::v1::Digest MakeDigest(
    google::cloud::kms::v1::Digest::DigestCase type,
    std::string digest_bytes);

}  // namespace proto_util
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_PROTO_UTIL_PROTO_MAKE_H_
