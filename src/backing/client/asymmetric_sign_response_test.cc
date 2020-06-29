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

#include "src/backing/client/asymmetric_sign_response.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

TEST(AsymmetricSignResponseTest, ConstructorSetsExpectedFields) {
  AsymmetricSignResponse response("my-signature");
  EXPECT_EQ(response.signature(), "my-signature");
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
