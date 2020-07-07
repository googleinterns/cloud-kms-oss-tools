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

#include "src/backing/client/proto_util/proto_make.h"

#include <memory>
#include <string>

#include <google/cloud/kms/v1/resources.grpc.pb.h>
#include <google/cloud/kms/v1/resources.pb.h>
#include <google/cloud/kms/v1/service.grpc.pb.h>
#include <google/cloud/kms/v1/service.pb.h>

namespace kmsengine {
namespace backing {
namespace proto_util {

using google::cloud::kms::v1::AsymmetricSignRequest;
using google::cloud::kms::v1::GetPublicKeyRequest;
using google::cloud::kms::v1::Digest;

AsymmetricSignRequest MakeAsymmetricSignRequest(
    std::string key_version_resource_id, Digest digest) {
  AsymmetricSignRequest proto_request;
  proto_request.set_name(std::move(key_version_resource_id));
  proto_request.mutable_digest()->CopyFrom(digest);
  return proto_request;
}

GetPublicKeyRequest MakeGetPublicKeyRequest(
    std::string key_version_resource_id) {
  GetPublicKeyRequest proto_request;
  proto_request.set_name(std::move(key_version_resource_id));
  return proto_request;
}

Digest MakeDigest(Digest::DigestCase type, std::string digest_bytes) {
  Digest proto_digest;
  auto moved_bytes = std::move(digest_bytes);
  switch (type) {
    case Digest::DigestCase::kSha256:
      proto_digest.set_sha256(moved_bytes);
      break;
    case Digest::DigestCase::kSha384:
      proto_digest.set_sha384(moved_bytes);
      break;
    case Digest::DigestCase::kSha512:
      proto_digest.set_sha512(moved_bytes);
      break;
    case Digest::DIGEST_NOT_SET:
      break;
  }
  return proto_digest;
}

}  // namespace proto_util
}  // namespace backing
}  // namespace kmsengine
