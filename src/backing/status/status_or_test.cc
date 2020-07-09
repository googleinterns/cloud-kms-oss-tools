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
 *    - Renamed namespaces and file includes
 *    - Updated tests to use IsOk matcher
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

#include "src/backing/status/status_or.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::testing::HasSubstr;
using ::testing::Not;

TEST(StatusOrTest, DefaultConstructor) {
  StatusOr<int> actual;
  EXPECT_FALSE(actual.ok());
  EXPECT_FALSE(actual.status().ok());
  EXPECT_THAT(actual, Not(IsOk()));
  EXPECT_THAT(actual.status(), Not(IsOk()));
}

TEST(StatusOrTest, StatusConstructorNormal) {
  StatusOr<int> actual(Status(StatusCode::kNotFound, "NOT FOUND"));
  EXPECT_THAT(actual, Not(IsOk()));
  EXPECT_EQ(StatusCode::kNotFound, actual.status().code());
  EXPECT_EQ("NOT FOUND", actual.status().message());
}

TEST(StatusOrTest, StatusAssignment) {
  auto const error = Status(StatusCode::kUnknown, "blah");
  StatusOr<int> sor;
  sor = error;
  EXPECT_FALSE(sor.ok());
  EXPECT_EQ(error, sor.status());
}

struct NoEquality {};

TEST(StatusOrTest, Equality) {
  auto const err1 = Status(StatusCode::kUnknown, "foo");
  auto const err2 = Status(StatusCode::kUnknown, "bar");

  EXPECT_EQ(StatusOr<int>(err1), StatusOr<int>(err1));
  EXPECT_NE(StatusOr<int>(err1), StatusOr<int>(err2));

  EXPECT_NE(StatusOr<int>(err1), StatusOr<int>(1));
  EXPECT_NE(StatusOr<int>(1), StatusOr<int>(err1));

  EXPECT_EQ(StatusOr<int>(1), StatusOr<int>(1));
  EXPECT_NE(StatusOr<int>(1), StatusOr<int>(2));

  // Verify that we can still construct a StatusOr with a type that does not
  // support equality, we just can't compare the StatusOr for equality with
  // anything else (obviously).
  StatusOr<NoEquality> no_equality;
  no_equality = err1;
  no_equality = NoEquality{};
}

TEST(StatusOrTest, ValueConstructor) {
  StatusOr<int> actual(42);
  EXPECT_THAT(actual, IsOk());
  EXPECT_TRUE(actual);
  EXPECT_EQ(42, actual.value());
  EXPECT_EQ(42, std::move(actual).value());
}

TEST(StatusOrTest, ValueConstAccessors) {
  StatusOr<int> const actual(42);
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(42, actual.value());
  EXPECT_EQ(42, std::move(actual).value());
}

TEST(StatusOrTest, StatusConstAccessors) {
  StatusOr<int> const actual(Status(StatusCode::kInternal, "BAD"));
  EXPECT_EQ(StatusCode::kInternal, actual.status().code());
  EXPECT_EQ(StatusCode::kInternal, std::move(actual).status().code());
}

TEST(StatusOrTest, ValueDeference) {
  StatusOr<std::string> actual("42");
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ("42", *actual);
  EXPECT_EQ("42", std::move(actual).value());
}

TEST(StatusOrTest, ValueConstDeference) {
  StatusOr<std::string> const actual("42");
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ("42", *actual);
  EXPECT_EQ("42", std::move(actual).value());
}

TEST(StatusOrTest, ValueArrow) {
  StatusOr<std::string> actual("42");
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(std::string("42"), actual->c_str());
}

TEST(StatusOrTest, ValueConstArrow) {
  StatusOr<std::string> const actual("42");
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(std::string("42"), actual->c_str());
}

}  // namespace
}  // namespace kmsengine
