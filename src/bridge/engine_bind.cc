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

#include <openssl/engine.h>

#include "src/bridge/engine_name.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/key_loader.h"
#include "src/bridge/rsa/rsa.h"
#include "src/backing/client/client_factory.h"

namespace kmsengine {
namespace bridge {
namespace {

// Initializes a `EngineData` structure for the Cloud KMS OpenSSL engine that
// contains the Cloud KMS `RSA_METHOD` implementation and an authenticated
// `Client`.
StatusOr<EngineData *> MakeDefaultEngineData() {
  // TODO(https://github.com/googleinterns/cloud-kms-oss-tools/issues/79): Add
  // support for setting a timeout duration in the OpenSSL configuration file.

  // `MakeDefaultClientWithoutTimeout` will automatically authenticate the
  // client using the Google Application Default Credentials strategy. See
  // https://cloud.google.com/docs/authentication/production#automatically for
  // more information.
  auto client = backing::MakeDefaultClientWithoutTimeout();

  auto rsa_method = rsa::MakeKmsRsaMethod();

  auto engine_data = new EngineData(std::move(client), std::move(rsa_method));
  if (engine_data == nullptr) {
    return Status(StatusCode::kResourceExhausted, "no memory available");
  }
  return engine_data;
}

// Initializes a "functional reference" to the Cloud KMS OpenSSL Engine.
// Specifically, it initializes the engine-specific substructures that are
// needed to provide the engine's intended cryptographic functionaliy (for
// example, an authenticated Cloud KMS API client). Returns 1 on success and 0
// if an error occurred.
//
// See https://www.openssl.org/docs/man1.1.0/man3/ENGINE_init.html for more
// information on "functional references".
//
// Function signature follows the `ENGINE_GEN_INT_FUNC_PTR` prototype from
// OpenSSL so `EngineBind` can use `ENGINE_set_init_function` to set
// `EngineInit` as the "init function" for the Cloud KMS engine. `EngineBind` is
// always called prior to calling `EngineInit`.
int EngineInit(ENGINE *e) {
  auto engine_data_or = MakeDefaultEngineData();
  if (!engine_data_or.ok()) {
    KMSENGINE_SIGNAL_ERROR(engine_data_or.status());
    return false;
  }
  auto engine_data = engine_data_or.value();

  auto attach_status = AttachEngineDataToOpenSslEngine(engine_data, e);
  if (!attach_status.ok()) {
    delete engine_data;
    KMSENGINE_SIGNAL_ERROR(attach_status);
    return false;
  }

  return true;
}

// Cleans up `ENGINE` substructures initialized in `EngineInit`. Returns 1 on
// success and 0 if an error occured.
//
// Function signature follows the `ENGINE_GEN_INT_FUNC_PTR` prototype from
// OpenSSL so `EngineBind` can use `ENGINE_set_finish_function` to set
// `EngineFinish` as the "finish function" for the Cloud KMS engine.
// `EngineFinish` is always called before `EngineDestroy`.
int EngineFinish(ENGINE *e) {
  auto engine_data_or = GetEngineDataFromOpenSslEngine(e);
  if (!engine_data_or.ok()) {
    KMSENGINE_SIGNAL_ERROR(engine_data_or.status());
    return false;
  }

  delete engine_data_or.value();

  auto attach_status = AttachEngineDataToOpenSslEngine(nullptr, e);
  if (!attach_status.ok()) {
    KMSENGINE_SIGNAL_ERROR(attach_status);
    return false;
  }

  return true;
}

// Destroys the ENGINE context.
//
// This function should perform any cleanup of structures that were created in
// EngineBind. It should also unload error strings.
//
// EngineFinish will have executed before EngineDestroy is called.
int EngineDestroy(ENGINE *e) {
  FreeExternalIndicies();
  return UnloadErrorStringsFromOpenSSL().ok();
}

}  // namespace

extern "C" int EngineBind(ENGINE *e, const char *id) {
  // We initialize external indicies in `EngineBind` as opposed to `EngineInit`
  // since the external indicies are global variables that all instances of the
  // Cloud KMS engine should share.
  auto init_status = InitExternalIndicies();
  if (!init_status.ok()) {
    KMSENGINE_SIGNAL_ERROR(init_status);
    return false;
  }

  // ENGINE_FLAGS_NO_REGISTER_ALL tells OpenSSL that our engine does not
  // supply implementations for all OpenSSL crypto methods.
  if (!ENGINE_set_id(e, kEngineId) ||
      !ENGINE_set_name(e, kEngineName) ||
      !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
      !ENGINE_set_load_privkey_function(e, LoadPrivateKey) ||
      !ENGINE_set_init_function(e, EngineInit) ||
      !ENGINE_set_finish_function(e, EngineFinish) ||
      !ENGINE_set_destroy_function(e, EngineDestroy)) {
    return false;
  }

  auto error_status = LoadErrorStringsIntoOpenSSL();
  if (!error_status.ok()) {
    KMSENGINE_SIGNAL_ERROR(error_status);
    return false;
  }

  return true;
}

}  // namespace bridge
}  // namespace kmsengine
