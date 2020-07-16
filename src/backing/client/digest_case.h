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

#ifndef KMSENGINE_BACKING_CLIENT_DIGEST_CASE_H_
#define KMSENGINE_BACKING_CLIENT_DIGEST_CASE_H_

#include <type_traits>

namespace kmsengine {
namespace backing {

// Represents the algorithm used to produce a particular Digest.
//
// Used in lieu of `google::cloud::kms::v1::Digest::DigestCase` from the Cloud
// KMS API protobuf definitions since the bridge layer needs to refer to this
// resource directly and the bridge layer is not able to include external
// dependencies (such as the generated protobuf definitions).
//
// Underlying values should match the underlying values of the corresponding
// cases in `google::cloud::kms::v1::Digest::DigestCase`; this allows for
// simple conversions between `DigestCase` and its protobuf counterpart by
// using `static_cast`.
enum class DigestCase : int {
  kSha256 = 1,
  kSha384 = 2,
  kSha512 = 3,
};

// Helper function for casting a `DigestCase` to its underlying type.
constexpr int DigestCaseToInt(DigestCase digest) {
  return static_cast<std::underlying_type<DigestCase>::type>(digest);
}

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_DIGEST_CASE_H_
