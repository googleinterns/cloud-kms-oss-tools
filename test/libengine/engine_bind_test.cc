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

#include "src/libengine/engine_bind.h"
#include "src/libengine/engine_name.h"

namespace libengine {
namespace {

// Test fixture for instantiating an OpenSSL ENGINE object.
class EngineBindTest : public ::testing::Test {
 protected:
  void SetUp() override {
    engine = ENGINE_new();
    ASSERT_NE(engine, nullptr);  // Sanity check for malloc errors.
  }

  void TearDown() override {
    ENGINE_free(engine);
  }

  ENGINE *engine;
};

TEST_F(EngineBindTest, SetsEngineId) {
  EngineBind(engine, NULL);
  EXPECT_STREQ(ENGINE_get_id(engine), kEngineId);
}

TEST_F(EngineBindTest, SetsEngineName) {
  EngineBind(engine, NULL);
  EXPECT_STREQ(ENGINE_get_name(engine), kEngineName);
}

TEST_F(EngineBindTest, SetsInitFunction) {
  EngineBind(engine, NULL);
  EXPECT_NE(ENGINE_get_init_function(engine), nullptr);
}

TEST_F(EngineBindTest, SetsFinishFunction) {
  EngineBind(engine, NULL);
  EXPECT_NE(ENGINE_get_finish_function(engine), nullptr);
}

TEST_F(EngineBindTest, SetsNoRegisterAllFlag) {
  EngineBind(engine, NULL);
  EXPECT_TRUE(ENGINE_get_flags(engine) & ENGINE_FLAGS_NO_REGISTER_ALL);
}

}  // namespace
}  // namespace libengine
