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

#ifndef KMSENGINE_TESTING_UTIL_MOCK_CLIENT_CONTEXT_FACTORY_H_
#define KMSENGINE_TESTING_UTIL_MOCK_CLIENT_CONTEXT_FACTORY_H_

#include <memory>

#include "grpcpp/grpcpp.h"
#include "src/backing/client/grpc_client/client_context_factory.h"

namespace kmsengine {
namespace testing_util {

class MockClientContextFactory :
    public ::kmsengine::backing::grpc_client::ClientContextFactory {
 public:
  MOCK_METHOD(std::unique_ptr<grpc::ClientContext>, MakeContext, (),
              (const, override));
};

}  // namespace testing_util
}  // namespace kmsengine

#endif  // KMSENGINE_TESTING_UTIL_MOCK_CLIENT_CONTEXT_FACTORY_H_
