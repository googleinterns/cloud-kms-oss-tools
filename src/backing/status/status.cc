/**
 * Protocol Buffers - Google's data interchange format
 * Copyright 2008 Google Inc.  All rights reserved.
 * https://developers.google.com/protocol-buffers/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Modifications copyright 2020 Google LLC:
 *
 *    - Renamed constants to match k-naming
 *    - Replaced references to StringPiece datatype with std::string
 *    - Changed Status.message and Status.error_message usage to reflect change
 *      from StringPiece datatype to std::string
 *    - Replaced StatusCodeToString function with absl::StatusCodeToString
 *
 * Modifications licensed under the Apache License, Version 2.0 (the "License");
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

#include "src/backing/status/status.h"

#include <stdio.h>

#include <ostream>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "src/backing/status/status_code.h"

namespace kmsengine {
namespace backing {
namespace status {

const Status Status::kOkStatus = Status();
const Status Status::kCancelledStatus = Status(StatusCode::kCancelled, "");
const Status Status::kUnknownStatus = Status(StatusCode::kUnknown, "");

Status::Status() : error_code_(StatusCode::kOk) {}

Status::Status(StatusCode error_code, std::string error_message)
    : error_code_(error_code) {
  if (error_code != StatusCode::kOk) {
    error_message_ = error_message;
  }
}

Status::Status(const Status& other)
    : error_code_(other.error_code_), error_message_(other.error_message_) {}

Status& Status::operator=(const Status& other) {
  error_code_ = other.error_code_;
  error_message_ = other.error_message_;
  return *this;
}

bool Status::operator==(const Status& x) const {
  return (error_code_ == x.error_code_) && (error_message_ == x.error_message_);
}

std::string Status::ToString() const {
  if (error_code_ == StatusCode::kOk) {
    return "OK";
  } else {
    if (error_message_.empty()) {
      return absl::StatusCodeToString(error_code_);
    } else {
      return absl::StatusCodeToString(error_code_) + ":" + error_message_;
    }
  }
}

std::ostream& operator<<(std::ostream& os, const Status& x) {
  os << x.ToString();
  return os;
}

}  // namespace status
}  // namespace backing
}  // namespace kmsengine
