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

#ifndef KMSENGINE_BACKING_CLIENT_PUBLIC_KEY_H_
#define KMSENGINE_BACKING_CLIENT_PUBLIC_KEY_H_

#include <string>

#include "src/backing/export_macros.h"
#include "src/backing/client/crypto_key_version_algorithm.h"

namespace kmsengine {
namespace backing {

// The public key for a Cloud KMS key.
//
// Used in lieu of `google::cloud::kms::v1::PublicKey` from the Cloud KMS API
// protobuf definitions since the bridge layer needs to refer to this resource
// directly and the bridge layer is not able to include external dependencies
// (such as the generated protobuf definitions).
class KMSENGINE_EXPORT PublicKey {
 public:
  explicit PublicKey(std::string pem, CryptoKeyVersionAlgorithm algorithm)
      : pem_(pem), algorithm_(algorithm) {}

  std::string const& pem() const { return pem_; }
  CryptoKeyVersionAlgorithm algorithm() const { return algorithm_; }

 private:
  std::string pem_;
  CryptoKeyVersionAlgorithm algorithm_;
};

inline bool operator==(PublicKey const& lhs, PublicKey const& rhs) {
  return lhs.pem() == rhs.pem() && lhs.algorithm() == rhs.algorithm();
}

inline bool operator!=(PublicKey const& lhs, PublicKey const& rhs) {
  return !(lhs == rhs);
}

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_PUBLIC_KEY_H_
