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

#ifndef ENGINE_ENGINE_H_
#define ENGINE_ENGINE_H_

#include "openssl/engine.h"

namespace engine {

class Engine {
 public:
  // Engine is not copyable.
  Engine(const Engine&) = delete;
  void operator=(const Engine&) = delete;

  // Initializes the OpenSSL ENGINE struct.
  static int BindOpenSSLEngine(ENGINE *e);

 private:
  static const char *kEngineId;
  static const char *kEngineName;

  Engine() {}

  static int OpenSSLInit(ENGINE *e);
};

}  // namespace engine

#endif  // ENGINE_ENGINE_H_
