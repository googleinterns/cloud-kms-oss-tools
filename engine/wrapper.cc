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


#include "wrapper.h"

#include <openssl/engine.h>

#include "engine/engine.h"

extern "C" {
// Binds the Cloud KMS engine implementations to the input ENGINE struct from
// OpenSSL. Returns 1 on success and 0 if an error occured.
//
// This is the main entry point from OpenSSL into the Cloud KMS Engine. OpenSSL
// calls this function when the engine shared object is loaded and passes it a
// fresh, non-null ENGINE struct. It is our code's responsibility to initialize
// the input struct using OpenSSL's ENGINE_set_* API functions.
int bind_function(ENGINE *e, const char *id) {
  return engine::Engine::BindOpenSSLEngine(e);
}


}
