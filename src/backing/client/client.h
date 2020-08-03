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

#ifndef KMSENGINE_BACKING_CLIENT_CLIENT_H_
#define KMSENGINE_BACKING_CLIENT_CLIENT_H_

#include <string>

#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {

// Defines the interface used to communicate with the Google Cloud KMS API.
class Client {
 public:
  virtual ~Client() = default;

  // Signs data using the CryptoKeyVersion `key_version_resource_id`. Produces
  // a signature that can be verified with the public key retrieved from
  // `GetPublicKey`.
  virtual StatusOr<std::string> AsymmetricSign(
      std::string key_version_resource_id, DigestCase digest_case,
      std::string digest_bytes) const = 0;

  // Returns the `PublicKey` for the given `key_version_resource_id`.
  virtual StatusOr<PublicKey> GetPublicKey(
      std::string key_version_resource_id) const = 0;
};

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_CLIENT_H_
