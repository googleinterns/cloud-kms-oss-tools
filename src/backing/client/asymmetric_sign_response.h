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

#ifndef KMSENGINE_BACKING_CLIENT_ASYMMETRIC_SIGN_RESPONSE_H_
#define KMSENGINE_BACKING_CLIENT_ASYMMETRIC_SIGN_RESPONSE_H_

#include <string>
#include <utility>

namespace kmsengine {
namespace backing {
namespace client {

// Represents metadata for a AsymmetricSignResponse from the Key Management
// Service API.
class AsymmetricSignResponse {
 public:
  AsymmetricSignResponse(std::string signature)
      : signature_(std::move(signature)) {}

  std::string const& signature() const { return signature_; }

 private:
  std::string signature_;
};

}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_ASYMMETRIC_SIGN_RESPONSE_H_
