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

#include "src/backing/rsa/kms_rsa_key.h"

#include <string>

#include "src/backing/client/client.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {

StatusOr<std::string> KmsRsaKey::Sign(DigestCase digest_type,
                                      std::string message_digest) {
  return client_.AsymmetricSign(key_resource_id(), digest_type,
                                message_digest);
}

StatusOr<PublicKey> KmsRsaKey::GetPublicKey() {
  return client_.GetPublicKey(key_resource_id());
}

}  // namespace backing
}  // namespace kmsengine
