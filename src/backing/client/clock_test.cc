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
 *    - Renamed namespaces
 *    - Renamed include paths
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

#include <memory>

#include <gmock/gmock.h>

#include "src/backing/client/clock.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

TEST(Clock, SteadyClock) {
  auto clock = std::make_shared<SteadyClock>();
  auto now = clock->Now();
  auto now2 = clock->Now();
  // `SteadyClock::Now()` can never decrease as physical time moves forward.
  EXPECT_LE(now, now2);
}

TEST(Clock, SystemClock) {
  auto clock = std::make_shared<SystemClock>();
  // There is no guarantee that `SystemClock::Now()` can never decrease, so
  // we can't test that like we do for `SteadyClock`, so for now just make
  // sure `Now()` is callable.
  (void)clock->Now();
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
