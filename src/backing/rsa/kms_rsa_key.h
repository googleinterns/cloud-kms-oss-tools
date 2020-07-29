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

#ifndef KMSENGINE_BACKING_RSA_KMS_RSA_KEY_H_
#define KMSENGINE_BACKING_RSA_KMS_RSA_KEY_H_

#include <string>

#include "src/backing/base_macros.h"
#include "src/backing/client/client.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {

// Implementation of RsaKey with Cloud KMS operations.
class BRIDGE_EXPORT KmsRsaKey : public RsaKey {
 public:
  KmsRsaKey(std::string key_resource_id, Client const& client)
    : key_resource_id_(key_resource_id), client_(client) {}
  ~KmsRsaKey() = default;

  // `KmsRsaKey` is copyable and moveable.
  KmsRsaKey(const KmsRsaKey& other) = default;
  KmsRsaKey& operator=(const KmsRsaKey& other) = default;

  // Getter for the Cloud KMS key resource ID.
  inline std::string const& key_resource_id() const { return key_resource_id_; }

  // RsaKey methods.
  BRIDGE_EXPORT StatusOr<std::string> Sign(DigestCase digest_type,
                             std::string message_digest) override;
  BRIDGE_EXPORT StatusOr<PublicKey> GetPublicKey() override;

 private:
  std::string key_resource_id_;
  Client const& client_;
};

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_RSA_KMS_RSA_KEY_H_
