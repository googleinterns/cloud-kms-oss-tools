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

#ifndef KMSENGINE_BACKING_STATUS_STATUS_H_
#define KMSENGINE_BACKING_STATUS_STATUS_H_

#include <iostream>
#include <tuple>

#include "src/backing/export_macros.h"

namespace kmsengine {

/**
 * Well-known status codes with `grpc::StatusCode`-compatible values.
 *
 * The semantics of these values are documented in:
 *     https://grpc.io/grpc/cpp/classgrpc_1_1_status.html
 */
enum class KMSENGINE_EXPORT StatusCode {
  /// Not an error; returned on success.
  kOk = 0,
  kCancelled = 1,
  kUnknown = 2,
  kInvalidArgument = 3,
  kDeadlineExceeded = 4,
  kNotFound = 5,
  kAlreadyExists = 6,
  kPermissionDenied = 7,
  kUnauthenticated = 16,
  kResourceExhausted = 8,
  kFailedPrecondition = 9,
  kAborted = 10,
  kOutOfRange = 11,
  kUnimplemented = 12,
  kInternal = 13,
  kUnavailable = 14,
  kDataLoss = 15,
};

inline int StatusCodeToInt(StatusCode code) {
  return static_cast<std::underlying_type<StatusCode>::type>(code);
}

KMSENGINE_EXPORT std::string StatusCodeToString(StatusCode code);
KMSENGINE_EXPORT std::ostream& operator<<(std::ostream& os, StatusCode code);

/**
 * Reports error code and details from a remote request.
 *
 * This class is modeled after `grpc::Status`, it contains the status code and
 * error message (if applicable) from a JSON request.
 */
class KMSENGINE_EXPORT Status {
 public:
  Status() = default;

  explicit Status(StatusCode status_code, std::string message)
      : code_(status_code), message_(std::move(message)) {}

  // "OK" status for convenience.
  static const Status kOk;

  bool ok() const { return code_ == StatusCode::kOk; }

  StatusCode code() const { return code_; }
  std::string const& message() const { return message_; }

 private:
  StatusCode code_{StatusCode::kOk};
  std::string message_;
};

inline std::ostream& operator<<(std::ostream& os, Status const& rhs) {
  return os << rhs.message() << " [" << StatusCodeToString(rhs.code()) << "]";
}

inline bool operator==(Status const& lhs, Status const& rhs) {
  return lhs.code() == rhs.code() && lhs.message() == rhs.message();
}

inline bool operator!=(Status const& lhs, Status const& rhs) {
  return !(lhs == rhs);
}

// Early-returns the status if it is in error; otherwise, proceeds.
//
// The argument expression is guaranteed to be evaluated exactly once.
#define KMSENGINE_RETURN_IF_ERROR(__status) \
  do {                                      \
    auto status = __status;                 \
    if (!status.ok()) {                     \
      return status;                        \
    }                                       \
  } while (false)

}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_STATUS_STATUS_H_
