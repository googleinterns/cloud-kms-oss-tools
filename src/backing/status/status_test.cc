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
 *    - Changed Status.message and Status.error_message usage to reflect change
 *      from StringPiece datatype to std::string
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

#include <stdio.h>

#include <gtest/gtest.h>

#include "src/backing/status/status.h"

namespace kmsengine {
namespace backing {
namespace status {
namespace {

TEST(Status, Empty) {
  Status status;
  EXPECT_EQ(StatusCode::kOk, Status::kOkStatus.error_code());
  EXPECT_EQ(StatusCode::kOk, Status::kOkStatus.code());
  EXPECT_EQ("OK", Status::kOkStatus.ToString());
}

TEST(Status, GenericCodes) {
  EXPECT_EQ(StatusCode::kOk, Status::kOkStatus.error_code());
  EXPECT_EQ(StatusCode::kOk, Status::kOkStatus.code());
  EXPECT_EQ(StatusCode::kCancelled, Status::kCancelledStatus.error_code());
  EXPECT_EQ(StatusCode::kCancelled, Status::kCancelledStatus.code());
  EXPECT_EQ(StatusCode::kUnknown, Status::kUnknownStatus.error_code());
  EXPECT_EQ(StatusCode::kUnknown, Status::kUnknownStatus.code());
}

TEST(Status, ConstructorZero) {
  Status status(StatusCode::kOk, "msg");
  EXPECT_TRUE(status.ok());
  EXPECT_EQ("OK", status.ToString());
}

TEST(Status, ErrorMessage) {
  Status status(StatusCode::kInvalidArgument, "");
  EXPECT_FALSE(status.ok());
  EXPECT_EQ("", status.error_message());
  EXPECT_EQ("", status.message());
  EXPECT_EQ("INVALID_ARGUMENT", status.ToString());
  status = Status(StatusCode::kInvalidArgument, "msg");
  EXPECT_FALSE(status.ok());
  EXPECT_EQ("msg", status.error_message());
  EXPECT_EQ("msg", status.message());
  EXPECT_EQ("INVALID_ARGUMENT:msg", status.ToString());
  status = Status(StatusCode::kOk, "msg");
  EXPECT_TRUE(status.ok());
  EXPECT_EQ("", status.error_message());
  EXPECT_EQ("", status.message());
  EXPECT_EQ("OK", status.ToString());
}

TEST(Status, Copy) {
  Status a(StatusCode::kUnknown, "message");
  Status b(a);
  ASSERT_EQ(a.ToString(), b.ToString());
}

TEST(Status, Assign) {
  Status a(StatusCode::kUnknown, "message");
  Status b;
  b = a;
  ASSERT_EQ(a.ToString(), b.ToString());
}

TEST(Status, AssignEmpty) {
  Status a(StatusCode::kUnknown, "message");
  Status b;
  a = b;
  std::string expected("OK");
  ASSERT_EQ(a.ToString(), expected);
  ASSERT_TRUE(b.ok());
  ASSERT_TRUE(a.ok());
}

TEST(Status, EqualsOK) {
  ASSERT_EQ(Status::kOkStatus, Status());
}

TEST(Status, EqualsSame) {
  const Status a = Status(StatusCode::kCancelled, "message");
  const Status b = Status(StatusCode::kCancelled, "message");
  ASSERT_EQ(a, b);
}

TEST(Status, EqualsCopy) {
  const Status a = Status(StatusCode::kCancelled, "message");
  const Status b = a;
  ASSERT_EQ(a, b);
}

TEST(Status, EqualsDifferentCode) {
  const Status a = Status(StatusCode::kCancelled, "message");
  const Status b = Status(StatusCode::kUnknown, "message");
  ASSERT_NE(a, b);
}

TEST(Status, EqualsDifferentMessage) {
  const Status a = Status(StatusCode::kCancelled, "message");
  const Status b = Status(StatusCode::kCancelled, "another");
  ASSERT_NE(a, b);
}

}  // namespace
}  // namespace status
}  // namespace backing
}  // namespace kmsengine
