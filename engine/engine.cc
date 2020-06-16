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

#include "engine/engine.h"

#include <openssl/engine.h>

#include "engine/rand.h"

namespace engine {

const char *Engine::kEngineId = "gcloudkms";
const char *Engine::kEngineName = "Google Cloud KMS Engine";

// Implements OpenSSL's RAND_METHOD declaration.
static const RAND_METHOD rand_method = {
  NULL,                   // seed
  RandMethod::bytes,      // bytes
  NULL,                   // cleanup
  NULL,                   // add
  NULL,                   // pseudorand
  RandMethod::status      // status
};

int Engine::BindOpenSSLEngine(ENGINE *e) {
  // ENGINE_FLAGS_NO_REGISTER_ALL tells OpenSSL that our engine does not
  // supply implementations for all OpenSSL crypto methods.
  if (!ENGINE_set_id(e, Engine::kEngineId) ||
      !ENGINE_set_name(e, Engine::kEngineName) ||
      !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
      !ENGINE_set_init_function(e, Engine::OpenSSLInit) ||
      !ENGINE_set_RAND(e, &rand_method)) {
    return 0;
  }

  // Load error strings.

  return 1;
}

int Engine::OpenSSLInit(ENGINE *e) {
  printf("Engine initialized!\n");
  return 1;
}

}  // namespace engine


