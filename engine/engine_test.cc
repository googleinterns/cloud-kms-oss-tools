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

#include "gtest/gtest.h"

namespace engine {
namespace {

TEST(EngineTest, EngineInitializes) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    ENGINE_load_dynamic();
    ENGINE *engine = ENGINE_by_id("hsm");
    ASSERT_TRUE(engine);

    // ENGINE_init returns non-zero on success.
    EXPECT_NE(ENGINE_init(engine), 0);
}

}  // namespace
}  // namespace hello
