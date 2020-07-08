// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef KMSENGINE_BACKING_STATUS_STATUS_H_
#define KMSENGINE_BACKING_STATUS_STATUS_H_

#include <iostream>
#include <tuple>

namespace kmsengine {

/**
 * Well-known status codes with `grpc::StatusCode`-compatible values.
 *
 * The semantics of these values are documented in:
 *     https://grpc.io/grpc/cpp/classgrpc_1_1_status.html
 */
enum class StatusCode {
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

std::string StatusCodeToString(StatusCode code);
std::ostream& operator<<(std::ostream& os, StatusCode code);

/**
 * Reports error code and details from a remote request.
 *
 * This class is modeled after `grpc::Status`, it contains the status code and
 * error message (if applicable) from a JSON request.
 */
class Status {
 public:
  Status() = default;

  explicit Status(StatusCode status_code, std::string message)
      : code_(status_code), message_(std::move(message)) {}

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

// Helper macros to create identifiers from concatenation.
#define __KMSENGINE_MACRO_CONCAT_INNER(__x, __y) __x##__y
#define __KMSENGINE_MACRO_CONCAT(__x, __y) \
  __KMSENGINE_MACRO_CONCAT_INNER(__x, __y)

// Implementation of KMSENGINE_ASSIGN_OR_RETURN that uses a unique temporary
// identifier for avoiding collision in the enclosing scope.
#define __KMSENGINE_ASSIGN_OR_RETURN_IMPL(__lhs, __rhs, __name) \
  auto __name = (__rhs);                                        \
  if (!__name.ok()) {                                           \
    return __name.status();                                     \
  }                                                             \
  __lhs = std::move(__name.value());

// Early-returns the status if it is in error; otherwise, assigns the
// right-hand-side expression to the left-hand-side expression.
//
// The right-hand-side expression is guaranteed to be evaluated exactly once.
//
// Note: KMSENGINE_ASSIGN_OR_RETURN expands into multiple statements; it cannot
// be used in a single statement (for example, within an `if` statement).
#define KMSENGINE_ASSIGN_OR_RETURN(__lhs, __rhs) \
  __KMSENGINE_ASSIGN_OR_RETURN_IMPL(             \
    __lhs, __rhs,                                \
    __KMSENGINE_MACRO_CONCAT(__status_or_value,  \
                             __COUNTER__))

}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_STATUS_STATUS_H_
