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

#ifndef KMSENGINE_TESTING_UTIL_OPENSSL_ASSERTIONS_H_
#define KMSENGINE_TESTING_UTIL_OPENSSL_ASSERTIONS_H_

#include <openssl/err.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/strings/string_view.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"

namespace kmsengine {
namespace testing_util {

// Helper function for formatting the custom assertion message.
inline testing::AssertionResult MakeFormattedAssertionFailure(
    absl::string_view message,
    absl::string_view expected,
    absl::string_view actual) {
  // Indentation for "Expected" and "Actual" follows googlemock ASSERT_* and
  // EXPECT_* formatting.
  return testing::AssertionFailure() << absl::StrFormat(
      "%s\n"
      "         Expected: %s\n"
      "           Actual: %s", message, expected, actual);
}

// Returns `testing::AssertionSuccess` if `openssl_return` is true. Otherwise,
// returns `testing::AssertionFailure` with a formatted message containing the
// first OpenSSL error in the OpenSSL error queue.
//
// Defined as a predicate instead of a matcher since matchers must be purely
// functional, but `ERR_get_error_line_data` has OpenSSL-internal side-effects.
testing::AssertionResult IsOpenSslSuccess(const char* expr,
                                          bool openssl_return) {
  if (openssl_return) return testing::AssertionSuccess();

  const char *file, *data;
  int line, flags;
  auto err = ERR_get_error_line_data(&file, &line, &data, &flags);

  // If err == 0, then no error was available in the OpenSSL error queue.
  if (err) {
    auto message = absl::StrFormat("%s unexpectedly returned false and "
                                   "produced OpenSSL error...", expr);
    auto actual = absl::StrFormat("false, with error in %s:%d [%s]", file, line,
                                  data);
    return MakeFormattedAssertionFailure(message, "success", actual);
  } else {
    auto message = absl::StrFormat("%s unexpectedly returned false...", expr);
    return MakeFormattedAssertionFailure(message, "success",
                                         "false (no OpenSSL error)");
  }
}

// Returns `testing::AssertionSuccess` if `openssl_return` is false and the
// first OpenSSL error in the OpenSSL error queue contains the substring
// `substr_error`. Otherwise, returns `testing::AssertionFailure`.
//
// Defined as a predicate instead of a matcher since matchers must be purely
// functional, but `ERR_get_error_line_data` has OpenSSL-internal side-effects.
testing::AssertionResult IsOpenSslFailure(const char* return_expr,
                                          const char* status_expr,
                                          bool openssl_return,
                                          const char* substr_error) {
  auto expected = absl::StrFormat("false with OpenSSL error containing '%s'",
                                  substr_error);
  if (openssl_return) {
    auto message = absl::StrFormat("%s unexpectedly returned true...",
                                   return_expr);
    return MakeFormattedAssertionFailure(message, expected, "true");
  }

  const char *file, *data;
  int line, flags;
  auto err = ERR_get_error_line_data(&file, &line, &data, &flags);

  // If err == 0, then no error was available in the OpenSSL error queue.
  if (!err) {
    auto message = absl::StrFormat("%s returned false, but did not produce "
                                   "OpenSSL error...", return_expr);
    return MakeFormattedAssertionFailure(message, expected,
                                         "false, but no OpenSSL error");
  }

  if (testing::Matches(testing::HasSubstr(substr_error))(data)) {
    return testing::AssertionSuccess();
  } else {
    auto message = absl::StrFormat("%s returned false and produced OpenSSL "
                                   "error, but OpenSSL error did not contain "
                                   "expected substring...", return_expr);
    auto actual = absl::StrFormat("false, with error in %s:%d [%s]", file, line,
                                  data);
    return MakeFormattedAssertionFailure(message, expected, actual);
  }
}

// Wrapper macros around the `IsOpenSslSuccess` predicate.
#define ASSERT_OPENSSL_SUCCESS(val) \
  ASSERT_PRED_FORMAT1(::kmsengine::testing_util::IsOpenSslSuccess, val)
#define EXPECT_OPENSSL_SUCCESS(val) \
  EXPECT_PRED_FORMAT1(::kmsengine::testing_util::IsOpenSslSuccess, val)

// Wrapper macros around the `IsOpenSslFailure` predicate.
#define ASSERT_OPENSSL_FAILURE(val, status) \
  ASSERT_PRED_FORMAT2(::kmsengine::testing_util::IsOpenSslFailure, val, status)
#define EXPECT_OPENSSL_FAILURE(val, status) \
  EXPECT_PRED_FORMAT2(::kmsengine::testing_util::IsOpenSslFailure, val, status)

}  // namespace testing_util
}  // namespace kmsengine

#endif  // KMSENGINE_TESTING_UTIL_OPENSSL_ASSERTIONS_H_
