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

#include "src/bridge/ex_data_util/ex_data_util.h"

#include <memory>

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/ex_data_util/engine_data.h"

namespace kmsengine {
namespace bridge {
namespace {

// Represents an uninitialized OpenSSL external index. Value is -1 since
// OpenSSL's `CRYPTO_get_ex_new_index` function for requesting external indicies
// returns -1 on failure.
constexpr int kUninitializedIndex = -1;

// External index assigned by OpenSSL on a `RSA` struct. If uninitialized, it
// has value `kUninitializedIndex`. Used in `AttachRsaKeyToOpenSslRsa` and
// `GetRsaKeyFromOpenSslRsa`.
int rsa_index = kUninitializedIndex;

// External index assigned by OpenSSL on a `ENGINE` struct. If uninitialized, it
// has value `kUninitializedIndex`. Used in `AttachEngineDataToOpenSslEngine`
// and `GetEngineDataFromOpenSslEngine`.
int engine_index = kUninitializedIndex;

// Requests an external index from OpenSSL for the index type `index_type`.
// Valid index types are the `CRYPTO_EX_INDEX_*` constants found in OpenSSL's
// crypto.h header.
//
// Returns the external index on success or an error `Status`.
StatusOr<int> GetIndex(int index_type) {
  // We ignore the argl and argp parameters (the second and third parameters)
  // since they're used in the callback functions (the fourth, fifth, and
  // sixth parameters), which we're just setting to `nullptr`.
  int index = CRYPTO_get_ex_new_index(index_type, 0, nullptr, nullptr,
                                      nullptr, nullptr);
  if (index == kUninitializedIndex) {
    return Status(StatusCode::kInternal, "No CRYPTO_EX_DATA index available");
  }
  return index;
}

// Returns `rsa_index` if it is initialized, or an error `Status`.
inline StatusOr<int> GetRsaIndex() {
  if (rsa_index == kUninitializedIndex) {
    return Status(StatusCode::kFailedPrecondition, "rsa_index uninitialized");
  }
  return rsa_index;
}

// Returns `engine_index` if it is initialized, or an error `Status`.
inline StatusOr<int> GetEngineIndex() {
  if (engine_index == kUninitializedIndex) {
    return Status(StatusCode::kFailedPrecondition,
                  "engine_index uninitialized");
  }
  return engine_index;
}

}  // namespace

Status InitExternalIndicies() {
  KMSENGINE_ASSIGN_OR_RETURN(rsa_index, GetIndex(CRYPTO_EX_INDEX_RSA));
  KMSENGINE_ASSIGN_OR_RETURN(engine_index, GetIndex(CRYPTO_EX_INDEX_ENGINE));
  return Status();
}

void FreeExternalIndicies() {
  CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, rsa_index);
  CRYPTO_free_ex_index(CRYPTO_EX_INDEX_ENGINE, engine_index);
  rsa_index = kUninitializedIndex;
  engine_index = kUninitializedIndex;
}

Status AttachRsaKeyToOpenSslRsa(backing::RsaKey *rsa_key, RSA *rsa) {
  if (rsa == nullptr) {
    return Status(StatusCode::kInvalidArgument, "RSA cannot be null");
  }

  KMSENGINE_ASSIGN_OR_RETURN(auto index, GetRsaIndex());
  if (!RSA_set_ex_data(rsa, index, static_cast<void *>(rsa_key))) {
    return Status(StatusCode::kInternal, "RSA_set_ex_data failed");
  }
  return Status();
}

StatusOr<backing::RsaKey *> GetRsaKeyFromOpenSslRsa(const RSA *rsa) {
  if (rsa == nullptr) {
    return Status(StatusCode::kInvalidArgument, "RSA cannot be null");
  }

  KMSENGINE_ASSIGN_OR_RETURN(auto index, GetRsaIndex());
  auto ex_data = RSA_get_ex_data(rsa, index);
  if (ex_data == nullptr) {
    return Status(StatusCode::kNotFound,
                  "RSA instance was not initialized with Cloud KMS data");
  }
  return static_cast<backing::RsaKey *>(ex_data);
}

Status AttachEngineDataToOpenSslEngine(EngineData *data, ENGINE *engine) {
  if (engine == nullptr) {
    return Status(StatusCode::kInvalidArgument, "ENGINE cannot be null");
  }

  KMSENGINE_ASSIGN_OR_RETURN(auto index, GetEngineIndex());
  if (!ENGINE_set_ex_data(engine, index, static_cast<void *>(data))) {
    return Status(StatusCode::kInternal, "ENGINE_set_ex_data failed");
  }
  return Status();
}

StatusOr<EngineData *> GetEngineDataFromOpenSslEngine(const ENGINE *engine) {
  if (engine == nullptr) {
    return Status(StatusCode::kInvalidArgument, "ENGINE cannot be null");
  }

  KMSENGINE_ASSIGN_OR_RETURN(auto index, GetEngineIndex());
  auto ex_data = ENGINE_get_ex_data(engine, index);
  if (ex_data == nullptr) {
    return Status(StatusCode::kNotFound,
                  "ENGINE instance was not initialized with Cloud KMS data");
  }
  return static_cast<EngineData *>(ex_data);
}

}  // namespace bridge
}  // namespace kmsengine
