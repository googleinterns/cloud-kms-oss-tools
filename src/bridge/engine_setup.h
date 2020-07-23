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

#ifndef KMSENGINE_BRIDGE_ENGINE_SETUP_H_
#define KMSENGINE_BRIDGE_ENGINE_SETUP_H_

#include <openssl/engine.h>

namespace kmsengine {
namespace bridge {

// Initializes a "functional reference" to the Cloud KMS OpenSSL Engine.
// Specifically, it initializes the engine-specific substructures that are
// needed to provide the engine's intended cryptographic functionaliy (for
// example, an authenticated Cloud KMS API client). Returns 1 on success and 0
// if an error occurred.
//
// See https://www.openssl.org/docs/man1.1.0/man3/ENGINE_init.html for more
// information on "functional references".
//
// Function signature follows the `ENGINE_GEN_INT_FUNC_PTR` prototype from
// OpenSSL so `EngineBind` can use `ENGINE_set_init_function` to set
// `EngineInit` as the "init function" for the Cloud KMS engine. `EngineBind` is
// always called prior to calling `EngineInit`.
int EngineInit(ENGINE *e);

// Cleans up `ENGINE` substructures initialized in `EngineInit`. Returns 1 on
// success and 0 if an error occured.
//
// Function signature follows the `ENGINE_GEN_INT_FUNC_PTR` prototype from
// OpenSSL so `EngineBind` can use `ENGINE_set_finish_function` to set
// `EngineFinish` as the "finish function" for the Cloud KMS engine.
// `EngineFinish` is always called before `EngineDestroy`.
int EngineFinish(ENGINE *e);

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_ENGINE_SETUP_H_
