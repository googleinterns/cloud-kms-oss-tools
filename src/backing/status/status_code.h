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

#ifndef KMSENGINE_KMS_INTERFACE_STATUS_STATUS_CODE_H_
#define KMSENGINE_KMS_INTERFACE_STATUS_STATUS_CODE_H_

#include <openssl/err.h>

#include "absl/status/status.h"

namespace kmsengine {
namespace backing {
namespace status {

// Defines "reason codes" for possible error cases in our engine. Codes are
// intended to be associated with human-readable error strings such that if our
// engine signals to OpenSSL that an error occured due to reason with code
// <code>, then OpenSSL will print out the human-readable string associated
// with <code>.
typedef absl::StatusCode StatusCode;

std::string StatusCodeToString(StatusCode code) {
  return absl::StatusCodeToString(code);
}

}  // namespace status
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_KMS_INTERFACE_STATUS_STATUS_CODE_H_
