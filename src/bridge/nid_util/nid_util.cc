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

#include "src/bridge/nid_util/nid_util.h"

#include <openssl/obj_mac.h>

#include "src/backing/client/digest_case.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace bridge {

using ::kmsengine::backing::DigestCase;

StatusOr<DigestCase> ConvertOpenSslNidToDigestType(int nid) {
  switch (nid) {
    case NID_sha256:
      return DigestCase::kSha256;
    case NID_sha384:
      return DigestCase::kSha384;
    case NID_sha512:
      return DigestCase::kSha512;
    default:
      return Status(StatusCode::kInvalidArgument, "Unsupported digest type");
  }
}

}  // namespace bridge
}  // namespace kmsengine
