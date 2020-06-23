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

#ifndef KMSENGINE_OPENSSL_INTERFACE_ENGINE_SETUP_H_
#define KMSENGINE_OPENSSL_INTERFACE_ENGINE_SETUP_H_

#include <openssl/engine.h>

namespace kmsengine {
namespace bridge {

// Initializes ENGINE substructures. Returns 1 on success and 0 if an error
// occured.
//
// Used as the init_function in the OpenSSL engine. EngineBind is always called
// prior to calling EngineInit.
int EngineInit(ENGINE *e);

// Cleans up ENGINE substructures. Returns 1 on success and 0 if an error
// occured.
//
// Used as the finish_function in the OpenSSL engine..
int EngineFinish(ENGINE *e);

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_OPENSSL_INTERFACE_ENGINE_SETUP_H_
