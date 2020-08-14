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

#include "src/bridge/crypto/rsa.h"
#include "src/bridge/engine_name.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/key_loader/key_loader.h"
#include "src/backing/client/client_factory.h"
#include "src/backing/client/client.h"

namespace kmsengine {
namespace bridge {
namespace {

// Initializes a `EngineData` structure for the Cloud KMS OpenSSL engine that
// contains the Cloud KMS `RSA_METHOD` implementation and an authenticated
// `Client`.
//
// This function returns a unique pointer instead of a raw pointer to simplify
// cleanup in caller error cases.
StatusOr<std::unique_ptr<EngineData>> MakeDefaultEngineData() {
  KMSENGINE_ASSIGN_OR_RETURN(
      OpenSslRsaMethod rsa_method, crypto::MakeKmsRsaMethod());

  auto engine_data = std::unique_ptr<EngineData>(
      new EngineData(backing::MakeDefaultClientWithoutTimeout(),
                     std::move(rsa_method),
                     // TODO (https://github.com/googleinterns/cloud-kms-oss-tools/pull/115):
                     // Add crypto::MakeKmsEcKeyMethod when #115 is merged in.
                     OpenSslEcKeyMethod(nullptr, nullptr)));
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
int EngineInit(ENGINE *engine) {
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      std::unique_ptr<EngineData> engine_data, MakeDefaultEngineData(), 0);

  // Attach Cloud KMS implementations of `RSA_METHOD` and `EC_KEY_METHOD` to
  // the OpenSSL `ENGINE`.
  if (!ENGINE_set_RSA(engine, engine_data->rsa_method()) ||
      !ENGINE_set_EC(engine, engine_data->ec_key_method())) {
    return 0;
  }

  KMSENGINE_RETURN_IF_OPENSSL_ERROR(
      AttachEngineDataToOpenSslEngine(std::move(engine_data), engine), 0);
  return 1;
}

// Cleans up `ENGINE` substructures initialized in `EngineInit`. Returns 1 on
// success and 0 if an error occured.
//
// Function signature follows the `ENGINE_GEN_INT_FUNC_PTR` prototype from
// OpenSSL so `EngineBind` can use `ENGINE_set_finish_function` to set
// `EngineFinish` as the "finish function" for the Cloud KMS engine.
// `EngineFinish` is always called before `EngineDestroy`.
int EngineFinish(ENGINE *engine) {
  // `GetEngineDataFromOpenSslEngine` guarantees that the return value is
  // non-null, so we can safely delete the returned pointer immediately.
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      EngineData *engine_data, GetEngineDataFromOpenSslEngine(engine), 0);
  delete engine_data;

  KMSENGINE_RETURN_IF_OPENSSL_ERROR(
      AttachEngineDataToOpenSslEngine(nullptr, engine), 0);
  return 1;
}

// Destroys the ENGINE context.
//
// This function should perform any cleanup of structures that were created in
// EngineBind. It should also unload error strings.
//
// EngineFinish will have executed before EngineDestroy is called.
int EngineDestroy(ENGINE *e) {
  KMSENGINE_RETURN_IF_OPENSSL_ERROR(UnloadErrorStringsFromOpenSSL(), 0);
  FreeExternalIndices();
  return 1;
}

}  // namespace

extern "C" int EngineBind(ENGINE *e, const char *id) {
  if (!ENGINE_set_id(e, kEngineId) ||
      !ENGINE_set_name(e, kEngineName) ||
      // ENGINE_FLAGS_NO_REGISTER_ALL tells OpenSSL that our engine does not
      // supply implementations for all OpenSSL crypto methods.
      !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
      !ENGINE_set_init_function(e, EngineInit) ||
      !ENGINE_set_finish_function(e, EngineFinish) ||
      !ENGINE_set_load_pubkey_function(e, LoadCloudKmsKey) ||
      !ENGINE_set_load_privkey_function(e, LoadCloudKmsKey) ||
      !ENGINE_set_destroy_function(e, EngineDestroy)) {
    return 0;
  }

  // Initialize subsystems needed for engine instances to work.
  KMSENGINE_RETURN_IF_OPENSSL_ERROR(InitExternalIndices(), 0);
  KMSENGINE_RETURN_IF_OPENSSL_ERROR(LoadErrorStringsIntoOpenSSL(), 0);
  return 1;
}

}  // namespace bridge
}  // namespace kmsengine
