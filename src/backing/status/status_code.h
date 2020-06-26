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

// Alias for absl::StatusCode. Used to define Status objects, which are in turn
// used to define StatusOr<T> objects.
//
// Defined at the top-level namespace for convenience.
using StatusCode = absl::StatusCode;

}  // namespace kmsengine

#endif  // KMSENGINE_KMS_INTERFACE_STATUS_STATUS_CODE_H_
