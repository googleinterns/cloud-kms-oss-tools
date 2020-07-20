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

#include <memory>
#include <string>

#include "src/backing/client/client.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/backing/rsa/rsa_key.h"

namespace kmsengine {
namespace backing {

// Implementation of RsaKey with Cloud KMS operations.
class KmsRsaKey : public RsaKey {
 public:
  KmsRsaKey(std::string key_resource_id,
            std::shared_ptr<Client> client_);

  // Getter for the Cloud KMS key resource ID.
  std::string const& key_resource_id() const { return key_resource_id_; }

  // RsaKey methods.
  StatusOr<std::string> PublicEncrypt(std::string message,
                                      int padding) override;
  StatusOr<std::string> PublicDecrypt(std::string message,
                                      int padding) override;
  StatusOr<std::string> PrivateEncrypt(std::string message,
                                       int padding) override;
  StatusOr<std::string> PrivateDecrypt(std::string message,
                                       int padding) override;
  StatusOr<std::string> Sign(DigestCase digest_type,
                             std::string message_digest) override;
  Status Verify(DigestCase digest_type,
                std::string message_digest,
                std::string signature) override;

 private:
  std::string key_resource_id_;
  std::shared_ptr<Client> client_;
};

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_RSA_KMS_RSA_KEY_H_