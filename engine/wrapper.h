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
#ifndef ENGINE_WRAPPER_H_
#define ENGINE_WRAPPER_H_

#ifdef __cplusplus
extern "C"
{
#endif  // __cplusplus

#include <openssl/engine.h>

int bind_function(ENGINE *e, const char *id);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // ENGINE_WRAPPER_H
