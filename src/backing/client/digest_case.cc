/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modifications copyright 2020 Google LLC
 *
 *    - Renamed namespaces and file includes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "src/backing/client/digest_case.h"

#include <sstream>
#include <string>

#include "absl/strings/str_format.h"

namespace kmsengine {
namespace backing {

std::string DigestCaseToString(DigestCase digest_case) {
  switch (digest_case) {
    case DigestCase::kSha256:
      return "SHA256";
    case DigestCase::kSha384:
      return "SHA384";
    case DigestCase::kSha512:
      return "SHA512";
    default:
      return absl::StrFormat("UNEXPECTED_DIGEST_CASE=%i",
                             static_cast<int>(digest_case));
  }
}

std::ostream& operator<<(std::ostream& os, DigestCase digest_case) {
  return os << DigestCaseToString(digest_case);
}

}  // namespace backing
}  // namespace kmsengine
