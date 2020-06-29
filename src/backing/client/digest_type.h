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

#ifndef KMSENGINE_BACKING_CLIENT_DIGEST_TYPE_H_
#define KMSENGINE_BACKING_CLIENT_DIGEST_TYPE_H_

namespace kmsengine {
namespace backing {
namespace client {

// Represents the algorithm used to produce a particular Digest.
//
// Underlying values should match the underlying values of
// `google.cloud.kms.v1.Digest` from the API's protobuf definition.
enum class DigestType : int {
  kSha256 = 1,
  kSha384 = 2,
  kSha512 = 3,
};

}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_DIGEST_TYPE_H_
