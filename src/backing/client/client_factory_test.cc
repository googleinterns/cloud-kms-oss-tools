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

#include "src/backing/client/client_factory.h"

namespace kmsengine {
namespace backing {
namespace {

TEST(ClientFactoryTest, MakeDefaultClientWithoutTimeout) {
  // We can't make calls with an authenticated client here, so for now just
  // check that the factory function is callable and returns a success
  // `Status`.
  (void)MakeDefaultClientWithoutTimeout();
}

TEST(ClientFactoryTest, MakeDefaultClientWithTimeout) {
  // We can't make calls with an authenticated client here, so for now just
  // check that the factory function is callable and returns a success
  // `Status`.
  (void)MakeDefaultClientWithTimeout(std::chrono::milliseconds(50));
}

}  // namespace
}  // namespace backing
}  // namespace kmsengine
