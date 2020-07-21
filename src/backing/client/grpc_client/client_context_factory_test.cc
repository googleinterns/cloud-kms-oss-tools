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

#include <chrono>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "src/backing/client/grpc_client/client_context_factory.h"
#include "src/backing/client/testing_util/fake_clock.h"

namespace kmsengine {
namespace backing {
namespace grpc_client {
namespace {

using ::kmsengine::backing::client::FakeSystemClock;
using ::kmsengine::backing::client::SystemClock;
using ::testing::Range;

class ClientContextFactoryTest : public
    testing::TestWithParam<std::chrono::milliseconds> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(DeadlineParameters, ClientContextFactoryTest,
                         Range(std::chrono::milliseconds(0),
                               std::chrono::milliseconds(1000),
                               std::chrono::milliseconds(50)));

TEST_P(ClientContextFactoryTest, MakeContextSetsDeadline) {
  auto timeout_duration = GetParam();
  auto fake_clock = std::make_shared<FakeSystemClock>();
  auto factory = CreateClientContextFactory(timeout_duration, fake_clock);

  // Some arbitrary amount of time passes after factory is instantiated.
  SystemClock real_clock;
  SystemClock::time_point time(real_clock.Now());
  fake_clock->SetTime(time);

  std::unique_ptr<grpc::ClientContext> context = factory->MakeContext();

  auto expected = time + timeout_duration;
  EXPECT_EQ(context->deadline(), expected);
}

}  // namespace
}  // namespace grpc_client
}  // namespace backing
}  // namespace kmsengine
