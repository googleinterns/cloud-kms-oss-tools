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

#include "src/bridge/engine_bind.h"

#include <openssl/engine.h>

#include "src/bridge/engine_name.h"
#include "src/bridge/engine_setup.h"
#include "src/bridge/error/error.h"
#include "src/bridge/key_loader.h"

namespace kmsengine {
namespace bridge {
namespace {

// Destroys the ENGINE context.
//
// This function should perform any cleanup of structures that were created in
// EngineBind. It should also unload error strings.
//
// EngineFinish will have executed before EngineDestroy is called.
int EngineDestroy(ENGINE *e) {
  UnloadErrorStringsFromOpenSSL();
  return 1;
}

}  // namespace

extern "C" int EngineBind(ENGINE *e, const char *id) {
  // ENGINE_FLAGS_NO_REGISTER_ALL tells OpenSSL that our engine does not
  // supply implementations for all OpenSSL crypto methods.
  if (!ENGINE_set_id(e, kEngineId) ||
      !ENGINE_set_name(e, kEngineName) ||
      !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
      !ENGINE_set_init_function(e, EngineInit) ||
      !ENGINE_set_finish_function(e, EngineFinish) ||
      !ENGINE_set_destroy_function(e, EngineDestroy) ||
      !ENGINE_set_load_privkey_function(e, LoadPrivateKey)) {
    return 0;
  }

  LoadErrorStringsIntoOpenSSL();
  return 1;
}

}  // namespace bridge
}  // namespace kmsengine
