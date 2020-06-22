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

#include "src/engine/engine_setup.h"

#include <openssl/engine.h>

namespace kmsengine {
namespace engine {

int EngineInit(ENGINE *e) {
  // TODO(zesp): Initialize necessary ex_data on ENGINE.
  printf("Engine initialized!\n");
  return 1;
}

int EngineFinish(ENGINE *e) {
  // TODO(zesp): Deallocate data initialized in EngineInit.
  return 1;
}

}  // namespace engine
}  // namespace kmsengine
