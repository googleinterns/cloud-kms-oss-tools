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

#include "src/bridge/engine_bind.h"

#include <memory>
#include <utility>

#include <openssl/engine.h>

#include "src/bridge/engine_name.h"
#include "src/bridge/engine_setup.h"
#include "src/bridge/error/error.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/bridge/engine_data.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/backing/client/client.h"
#include "src/bridge/rsa/rsa.h"
#include "src/backing/client/client_factory.h"

namespace kmsengine {
namespace bridge {
namespace {

// Destroys the ENGINE context.
//
// This function should perform any cleanup of structures that were created in
// EngineBind. It should also unload error strings.
//
// EngineFinish will have executed before EngineDestroy is called.
int EngineDestroy(ENGINE *e) {
  auto engine_data_or = GetEngineDataFromOpenSslEngine(e);
  if (engine_data_or.ok()) delete engine_data_or.value();

  auto unload_status = UnloadErrorStringsFromOpenSSL();

  // Return 1 if everything was successful; otherwise, return 0.
  return (engine_data_or.ok() && unload_status.ok());
}

}  // namespace

extern "C" int EngineBind(ENGINE *e, const char *id) {
  auto init_status = InitExternalIndicies();
  if (!init_status.ok()) {
    KMSENGINE_SIGNAL_ERROR(init_status);
    return 0;
  }

  std::unique_ptr<backing::Client> client = backing::MakeDefaultClientWithoutTimeout();
  OpenSslRsaMethod rsa_method = rsa::MakeKmsRsaMethod();
  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));

  auto attach_status = AttachEngineDataToOpenSslEngine(engine_data, e);
  if (!attach_status.ok()) {
    delete engine_data;
    KMSENGINE_SIGNAL_ERROR(attach_status);
    return 0;
  }

  // ENGINE_FLAGS_NO_REGISTER_ALL tells OpenSSL that our engine does not
  // supply implementations for all OpenSSL crypto methods.
  if (!ENGINE_set_id(e, kEngineId) ||
      !ENGINE_set_name(e, kEngineName) ||
      !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
      !ENGINE_set_init_function(e, EngineInit) ||
      !ENGINE_set_finish_function(e, EngineFinish) ||
      !ENGINE_set_destroy_function(e, EngineDestroy)) {
    return 0;
  }

  LoadErrorStringsIntoOpenSSL();
  return 1;
}

}  // namespace bridge
}  // namespace kmsengine
