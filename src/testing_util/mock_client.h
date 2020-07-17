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

#ifndef KMSENGINE_TESTING_UTIL_MOCK_CLIENT_H_
#define KMSENGINE_TESTING_UTIL_MOCK_CLIENT_H_

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "src/backing/client/client.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace testing_util {

class MockClient : public ::kmsengine::backing::Client {
 public:
  MOCK_METHOD(StatusOr<std::string>, AsymmetricSign,
              (std::string key_version_resource_id, backing::DigestCase
               digest_case, std::string digest_bytes),
              (override));
  MOCK_METHOD(StatusOr<std::unique_ptr<backing::PublicKey>>, GetPublicKey,
              (std::string key_version_resource_id), (override));
};

}  // namespace testing_util
}  // namespace kmsengine

#endif  // KMSENGINE_TESTING_UTIL_MOCK_CLIENT_H_
