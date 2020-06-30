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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "src/backing/client/grpc_client_impl/grpc_client_context_factory.h"
#include "src/backing/client/testing_util/fake_clock.h"

namespace kmsengine {
namespace backing {
namespace client {
namespace grpc_client_impl {
namespace {

using ::kmsengine::backing::client::testing_util::FakeSystemClock;

TEST(GrpcClientContextFactoryTest, MakeContextSetsDeadline) {
  const std::chrono::milliseconds kTestTimeoutDurations[] = {
    std::chrono::milliseconds(150),
    std::chrono::milliseconds(500),
    std::chrono::seconds(10),
    std::chrono::minutes(1),
  };

  for (auto timeout_duration : kTestTimeoutDurations) {
    // In the CI environment `grpc::GoogleDefaultCredentials()` may assert. Use
    // the insecure credentials to initialize the options in any unit test.
    std::shared_ptr<GrpcClientOptions> options =
        std::make_shared<GrpcClientOptions>(grpc::InsecureChannelCredentials());
    options->set_timeout_duration(timeout_duration);

    std::shared_ptr<FakeSystemClock> fake_clock =
        std::make_shared<FakeSystemClock>();
    GrpcClientContextFactory factory(options, fake_clock);

    // Some arbitrary amount of time passes after factory is instantiated.
    SystemClock real_clock;
    SystemClock::time_point time(real_clock.Now());
    fake_clock->SetTime(time);

    std::unique_ptr<grpc::ClientContext> context = factory.MakeContext();

    auto expected = time + timeout_duration;
    EXPECT_EQ(context->deadline(), expected);
  }
}

}  // namespace
}  // namespace grpc_client_impl
}  // namespace client
}  // namespace backing
}  // namespace kmsengine
