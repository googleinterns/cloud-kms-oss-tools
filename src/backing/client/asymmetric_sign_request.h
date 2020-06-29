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

#ifndef KMSENGINE_BACKING_CLIENT_ASYMMETRIC_SIGN_REQUEST_H_
#define KMSENGINE_BACKING_CLIENT_ASYMMETRIC_SIGN_REQUEST_H_

#include <string>
#include <utility>

#include "src/backing/client/digest.h"

namespace kmsengine {
namespace backing {
namespace client {

// Represents metadata for a AsymmetricSignRequest from the Key Management
// Service API.
class AsymmetricSignRequest {
 public:
  // `key_name` is the resource name of the google.cloud.kms.v1.CryptoKeyVersion
  // to use for signing. `digest` holds the digest of the data to sign.
  AsymmetricSignRequest(std::string key_name, Digest digest)
      : key_name_(std::move(key_name)),
        digest_(std::move(digest)) {}

  std::string const& KeyName() const { return key_name_; }
  Digest const& Digest() const { return digest_; }

 private:
  std::string key_name_;
  Digest digest_;
};

}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_ASYMMETRIC_SIGN_REQUEST_H_
