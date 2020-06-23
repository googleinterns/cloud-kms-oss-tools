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

#include <openssl/engine.h>
#include <gtest/gtest.h>

#include "src/engine/engine_bind.h"
#include "src/engine/engine_name.h"

namespace kmsengine {
namespace engine {
namespace {

TEST(EngineBindTest, InitializesExpectedEngineStructFields) {
  ENGINE *engine = ENGINE_new();
  ASSERT_NE(engine, nullptr);  // Sanity check for malloc errors.

  EngineBind(engine, NULL);
  EXPECT_STREQ(ENGINE_get_id(engine), kEngineId);
  EXPECT_STREQ(ENGINE_get_name(engine), kEngineName);
  EXPECT_NE(ENGINE_get_init_function(engine), nullptr);
  EXPECT_NE(ENGINE_get_finish_function(engine), nullptr);
  EXPECT_TRUE(ENGINE_get_flags(engine) & ENGINE_FLAGS_NO_REGISTER_ALL);

  ENGINE_free(engine);
}

}  // namespace
}  // namespace engine
}  // namespace kmsengine
