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

#ifndef KMSENGINE_BACKING_CLIENT_DIGEST_H_
#define KMSENGINE_BACKING_CLIENT_DIGEST_H_

#include <string>
#include <utility>

#include "src/backing/client/digest_type.h"

namespace kmsengine {
namespace backing {
namespace client {

// Represents metadata for a Digest from the Key Management Service API. Holds
// a cryptographic message digest produced by the algorithm denoted by the
// given DigestType.
class Digest {
 public:
  Digest(DigestType type, std::string bytes) : type_(std::move(type)),
                                               bytes_(std::move(bytes)) {}

  DigestType const& type() const { return type_; }
  std::string const& bytes() const { return bytes_; }

 private:
  DigestType type_;
  std::string bytes_;
};

}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_DIGEST_H_
