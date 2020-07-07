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

#ifndef KMSENGINE_BACKING_STATUS_STATUS_OR_H_
#define KMSENGINE_BACKING_STATUS_STATUS_OR_H_

#include "google/cloud/status.h"
#include "google/cloud/status_or.h"

namespace kmsengine {

// Status-related definitions imported from the Google Cloud C++ client
// library.
//
// Aliases are exported at the top-level namespace for convenience across the
// codebase.

// Well-known status codes with values compatible with `grpc::StatusCode` and
// `absl::StatusCode`.
//
// See https://grpc.github.io/grpc/core/md_doc_statuscodes.html for the
// semantics of status code values.
using StatusCode = google::cloud::StatusCode;

// Reports error code and details.
using Status = google::cloud::Status;

// Holds a value or a `Status` indicating why there is no value.
template<typename T>
using StatusOr = google::cloud::StatusOr<T>;

// Converts the `StatusCode` to its underlying integer type.
//
// Useful for testing as well as defining error strings.
constexpr int StatusCodeToInt(StatusCode code) {
  return static_cast<std::underlying_type<StatusCode>::type>(code);
}

const auto StatusCodeToString = google::cloud::StatusCodeToString;

}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_STATUS_STATUS_OR_H_
