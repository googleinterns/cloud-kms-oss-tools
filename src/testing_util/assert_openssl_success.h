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

#ifndef KMSENGINE_TESTING_UTIL_ASSERT_OPENSSL_SUCCESS_H_
#define KMSENGINE_TESTING_UTIL_ASSERT_OPENSSL_SUCCESS_H_

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace kmsengine {
namespace testing_util {

testing::AssertionResult IsOpenSslSuccess(bool openssl_return) {
  if (openssl_return) {
    return testing::AssertionSuccess();
  }

  const char *file, *data;
  int line, flags;
  auto err = ERR_get_error_line_data(&file, &line, &data, &flags);

  return testing::AssertionFailure()
         << "Expected: success\nActual: error in " << file << " at " << line
         << "(" << data << ")";
}

#define ASSERT_OPENSSL_SUCCESS(val) \
  ASSERT_PRED_FORMAT1(::kmsengine::testing_util::IsOpenSslSuccess, val)

}  // namespace testing_util
}  // namespace kmsengine

#endif  // KMSENGINE_TESTING_UTIL_ASSERT_OPENSSL_SUCCESS_H_
