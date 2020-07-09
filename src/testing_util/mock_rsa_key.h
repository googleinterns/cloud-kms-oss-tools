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

#ifndef KMSENGINE_TESTING_UTIL_MOCK_RSA_KEY_H_
#define KMSENGINE_TESTING_UTIL_MOCK_RSA_KEY_H_

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "src/backing/rsa/rsa_key.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace bridge {
namespace rsa {
namespace testing_util {

class MockRsaKey : public RsaKey {
 public:
  MOCK_METHOD(StatusOr<std::string>, PublicEncrypt,
              (std::string message, int padding), (override));
  MOCK_METHOD(StatusOr<std::string>, PublicDecrypt,
              (std::string message, int padding), (override));
  MOCK_METHOD(StatusOr<std::string>, PrivateEncrypt,
              (std::string message, int padding), (override));
  MOCK_METHOD(StatusOr<std::string>, PrivateDecrypt,
              (std::string message, int padding), (override));
  MOCK_METHOD(StatusOr<std::string>, Sign, (DigestCase type,
                                            std::string message_digest),
              (override));
  MOCK_METHOD(Status, Verify, (DigestCase type,
                               std::string message_digest,
                               std::string signature),
              (override));
};

}  // namespace testing_util
}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_TESTING_UTIL_MOCK_RSA_KEY_H_
