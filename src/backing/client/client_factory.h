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

#ifndef KMSENGINE_BACKING_CLIENT_CLIENT_FACTORY_H_
#define KMSENGINE_BACKING_CLIENT_CLIENT_FACTORY_H_

#include <chrono>
#include <memory>

#include "src/backing/export_macros.h"
#include "src/backing/client/client.h"

namespace kmsengine {
namespace backing {

// Makes the default client with the given timeout.
KMSENGINE_EXPORT std::unique_ptr<Client> MakeDefaultClientWithTimeout(
    std::chrono::milliseconds timeout);

// Makes the default client, except without a timeout.
//
// Separate function is defined as opposed to using `absl::optional` since
// the bridge layer is unable to have Abseil as a dependency.
KMSENGINE_EXPORT std::unique_ptr<Client> MakeDefaultClientWithoutTimeout();

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_CLIENT_FACTORY_H_
