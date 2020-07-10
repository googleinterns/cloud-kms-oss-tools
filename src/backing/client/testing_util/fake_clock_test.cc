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

#include <gmock/gmock.h>
#include <memory>

#include "src/backing/client/clock.h"
#include "src/backing/client/testing_util/fake_clock.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace {

using ::kmsengine::backing::client::testing_util::FakeClock;

TEST(Clock, FakeClock) {
  SteadyClock real_clock;
  FakeClock<SteadyClock> clock;
  SteadyClock::time_point time(real_clock.Now());
  clock.SetTime(time);
  EXPECT_EQ(clock.Now(), time);

  time += std::chrono::minutes(3);
  clock.SetTime(time);
  EXPECT_EQ(clock.Now(), time);

  SteadyClock::duration duration = std::chrono::hours(89);
  time += duration;
  clock.AdvanceTime(duration);
  EXPECT_EQ(clock.Now(), time);
  time += duration;
  clock.AdvanceTime(duration);
  EXPECT_EQ(clock.Now(), time);
}

}  // namespace
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
