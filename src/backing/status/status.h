// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// https://developers.google.com/protocol-buffers/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#ifndef KMSENGINE_BACKING_STATUS_STATUS_H_
#define KMSENGINE_BACKING_STATUS_STATUS_H_

#include <iosfwd>
#include <string>

#include "src/backing/status/status_code.h"

namespace kmsengine {
namespace backing {
namespace status {

class Status {
 public:
  // Creates a "successful" status.
  Status();

  // Create a status in the canonical error space with the specified
  // code, and error message.  If "code == StatusCode::kOk", error_message is
  // ignored and a Status object identical to Status::OK is
  // constructed.
  Status(StatusCode error_code, std::string error_message);
  Status(const Status&);
  Status& operator=(const Status& x);
  ~Status() {}

  // Some pre-defined Status objects
  static const Status kOkStatus;             // Identical to 0-arg constructor
  static const Status kCancelledStatus;
  static const Status kUnknownStatus;

  // Accessor
  bool ok() const {
    return error_code_ == StatusCode::kOk;
  }
  StatusCode error_code() const {
    return error_code_;
  }
  StatusCode code() const {
    return error_code_;
  }
  std::string error_message() const {
    return error_message_;
  }
  std::string message() const {
    return error_message_;
  }

  bool operator==(const Status& x) const;
  bool operator!=(const Status& x) const {
    return !operator==(x);
  }

  // Return a combination of the error code name and message.
  std::string ToString() const;

 private:
  StatusCode error_code_;
  std::string error_message_;
};

// Prints a human-readable representation of 'x' to 'os'.
std::ostream& operator<<(std::ostream& os, const Status& x);

}  // namespace status
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_STATUS_STATUS_H_
