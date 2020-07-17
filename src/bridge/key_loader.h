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

#ifndef KMSENGINE_BRIDGE_KEY_LOADER_H_
#define KMSENGINE_BRIDGE_KEY_LOADER_H_

#include <openssl/engine.h>

#include "src/backing/rsa/kms_rsa_key.h"
#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::backing::KmsRsaKey;
using ::kmsengine::backing::RsaKey;

// Implementation of `KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR` that uses
// a unique temporary identifier for avoiding collision in the enclosing scope.
#define __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL(__lhs, __rhs, __name) \
  auto __name = (__rhs);                                                   \
  if (!__name.ok()) {                                                      \
    KMSENGINE_SIGNAL_ERROR(__name.status());                               \
    return nullptr;                                                          \
  }                                                                        \
  __lhs = std::move(__name.value());

// Signals an engine error to OpenSSL using the given StatusOr<T> and returns
// nullptr if it is an error status; otherwise, assigns the underlying
// StatusOr<T> value to the left-hand-side expression. Should be used only in
// engine-defined OpenSSL callbacks (for example, `RSA_METHOD` callbacks), since
// the returned "nullptr" value is intended for OpenSSL.
//
// The right-hand-side expression is guaranteed to be evaluated exactly once.
//
// Note: KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR expands into multiple
// statements; it cannot be used in a single statement (for example, within an
// `if` statement).
#define KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(__lhs, __rhs) \
  __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL(                     \
    __lhs, __rhs,                                                   \
    __KMSENGINE_MACRO_CONCAT(__status_or_value, __COUNTER__))

// Creates an `OpenSslRsa` initialized with a `KmsRsaKey` and the `RSA_METHOD`
// attached to `engine_data, or returns an error `Status`.
//
// The underlying `KmsRsaKey` is initialized using the `Client` attached to
// `engine_data` and the input `key_resource_id`.
StatusOr<OpenSslRsa> MakeRsaWithKmsKey(EngineData *engine_data,
                                       std::string key_resource_id) {
  // We initialize these as smart pointers even though we have to eventually
  // release them to OpenSSL as raw pointers since it simplifies cleanup in
  // the error cases.
  auto rsa = MakeRsa();
  auto rsa_key = std::unique_ptr<RsaKey>(new KmsRsaKey(key_resource_id,
                                                       engine_data->client()));
  if (rsa == nullptr || rsa_key == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
  }

  if (!RSA_set_method(rsa.get(), engine_data->rsa_method())) {
    return Status(StatusCode::kInternal, "RSA_set_method failed");
  }

  // If successful, pass ownership of `RsaKey` to the `RSA` struct.
  KMSENGINE_RETURN_IF_ERROR(AttachRsaKeyToOpenSslRsa(rsa_key.get(), rsa.get()));
  rsa_key.release();
  return rsa;
}

// Creates an `OpenSslEvpPkey` with the underlying pkey as the input
// `OpenSslRsa`, or returns an error `Status`.
//
// The resulting `EVP_PKEY` will have `EVP_PKEY_type(pkey) == EVP_PKEY_RSA`.
StatusOr<OpenSslEvpPkey> MakeRsaEvpPkey(OpenSslRsa rsa) {
  // We initialize `EVP_PKEY` as a smart pointer even though we have to
  // eventually release it to OpenSSL as a raw pointer since it simplifies
  // cleanup in the error cases.
  auto evp_pkey = MakeEvpPkey();
  if (evp_pkey == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
  }

  // Once we assign the `RSA` struct to the `EVP_PKEY`, the `EVP_PKEY` assumes
  // ownership of `RSA` so we need to release the smart pointer here.
  if (!EVP_PKEY_assign_RSA(evp_pkey.get(), rsa.get())) {
    return Status(StatusCode::kInternal, "EVP_PKEY_assign_RSA failed");
  }
  rsa.release();
  return evp_pkey;
}

}  // namespace

// Loads a Cloud HSM private key from the `key_id` file.
//
// Implements the `ENGINE_LOAD_KEY_PTR` prototype from OpenSSL for use with
// the `ENGINE_set_load_privkey_function` API function. OpenSSL will call
// this function directly and pass it the `key_id` specified by the end
// application.
//
// The `ui_method` and `callback_data` parameters are ignored.
//
// TODO(zesp): This is currently just treating the `key_id` path as the Cloud
// KMS key resource ID itself. It may be useful to let the user instead specify
// a real file that contains the key resource ID in it instead.
EVP_PKEY *LoadPrivateKey(ENGINE *openssl_engine, const char *key_id,
                         UI_METHOD *ui_method, void *callback_data) {
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto engine_data, GetEngineDataFromOpenSslEngine(openssl_engine));
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto kms_rsa, MakeRsaWithKmsKey(engine_data, key_id));
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      auto kms_evp_pkey, MakeRsaEvpPkey(std::move(kms_rsa)));
  return kms_evp_pkey.release();
}

#undef __KMSENGINE_ASSIGN_OR_RETURN_WITH_ERROR_IMPL
#undef KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_KEY_LOADER_H_
