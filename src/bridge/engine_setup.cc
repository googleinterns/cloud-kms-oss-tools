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

#include "src/bridge/engine_setup.h"

#include <utility>

#include <openssl/engine.h>

#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/rsa/rsa.h"
#include "src/backing/client/client_factory.h"

namespace kmsengine {
namespace bridge {
namespace {

StatusOr<EngineData *> MakeDefaultEngineData() {
  auto client = backing::MakeDefaultClientWithoutTimeout();
  auto rsa_method = rsa::MakeKmsRsaMethod();

  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  if (engine_data == nullptr) {
    return Status(StatusCode::kResourceExhausted, "no memory available");
  }
  return engine_data;
}

}  // namespace

int EngineInit(ENGINE *e) {
  auto engine_data_or = MakeDefaultEngineData();
  if (!engine_data_or.ok()) {
    KMSENGINE_SIGNAL_ERROR(engine_data_or.status());
    return 0;
  }
  auto engine_data = engine_data_or.value();

  auto attach_status = AttachEngineDataToOpenSslEngine(engine_data, e);
  if (!attach_status.ok()) {
    delete engine_data;
    KMSENGINE_SIGNAL_ERROR(attach_status);
    return 0;
  }

  return 1;
}

int EngineFinish(ENGINE *e) {
  auto engine_data_or = GetEngineDataFromOpenSslEngine(e);
  if (!engine_data_or.ok()) {
    KMSENGINE_SIGNAL_ERROR(engine_data_or.status());
    return 0;
  }

  delete engine_data_or.value();
  return 1;
}

}  // namespace bridge
}  // namespace kmsengine
