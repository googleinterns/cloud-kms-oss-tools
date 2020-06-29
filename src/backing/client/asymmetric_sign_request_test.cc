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

#include <gtest/gtest.h>

#include "src/backing/client/asymmetric_sign_request.h"
#include "src/backing/client/digest.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

TEST(AsymmetricSignRequestTest, ConstructorSetsExpectedFields) {
  Digest digest(DigestType::kSha256, "some-digest");
  AsymmetricSignRequest request("my-key-name", digest);
  EXPECT_EQ(request.key_name(), "my-key-name");
  EXPECT_EQ(request.digest().type(), DigestType::kSha256);
  EXPECT_EQ(request.digest().bytes(), "some-digest");
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
