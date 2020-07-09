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

#ifndef KMSENGINE_BRIDGE_NID_UTIL_NID_UTIL_H_
#define KMSENGINE_BRIDGE_NID_UTIL_NID_UTIL_H_

#include "src/backing/client/digest_case.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace bridge {

// Converts a OpenSSL NID to a `DigestType`. Returns a Status if the input
// `nid` does not match a defined `DigestType`.
//
// Valid NIDs to this function are:
//
//    - The underlying `EVP_MD_type` of `EVP_sha256`
//    - The underlying `EVP_MD_type` of `EVP_sha384`
//    - The underlying `EVP_MD_type` of `EVP_sha512`
//
// All other NIDs will result in an error status return value.
StatusOr<backing::DigestCase> ConvertOpenSslNidToDigestType(int nid);

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_NID_UTIL_NID_UTIL_H_
