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

#ifndef LIBENGINE_ENGINE_BIND_H_
#define LIBENGINE_ENGINE_BIND_H_

// extern "C" is used to expose engine_bind as a pure C function to OpenSSL's
// engine macros.
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <openssl/engine.h>

// Binds the Cloud KMS engine implementations to the input ENGINE struct from
// OpenSSL. Returns 1 on success and 0 if an error occured.
//
// This is the main entry point from OpenSSL into the Cloud KMS Engine. OpenSSL
// calls this function when the engine shared object is loaded and passes it a
// fresh, non-null ENGINE struct. Our code is responsible for initializing
// the input struct using OpenSSL's ENGINE_set_* API functions.
int engine_bind(ENGINE *e, const char *id);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // LIBENGINE_ENGINE_BIND_H_
