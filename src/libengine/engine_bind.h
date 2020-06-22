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

#include <openssl/engine.h>

// Binds the Cloud KMS engine implementations to the input ENGINE struct from
// OpenSSL. Returns 1 on success and 0 if an error occured.
//
// This is the main entry point from OpenSSL into the Cloud KMS Engine. OpenSSL
// calls this function when the engine shared object is loaded and passes it a
// fresh, non-null ENGINE struct. Our code is responsible for initializing
// the input struct using OpenSSL's ENGINE_set_* API functions.
//
// This function is exposed as a pure C name (via `extern "C"`) so that we can
// pass the OpenSSL IMPLEMENT_DYNAMIC_BIND_FN macro a pure C name as opposed to
// a C++ name. Passing a C++ name to the macro directly may cause C++'s
// name-mangling to break the macro; for example, if the macro implementation
// defines new functions based on the name of the input function.
#ifdef __cplusplus
extern "C"
#endif  // __cplusplus
int EngineBind(ENGINE *e, const char *id);

#endif  // LIBENGINE_ENGINE_BIND_H_
