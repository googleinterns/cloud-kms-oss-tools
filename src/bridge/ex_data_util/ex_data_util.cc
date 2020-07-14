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

#include "src/backing/client/client.h"
#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace bridge {
namespace {

// OpenSSL CRYPTO_get_ex_new_index returns -1 on failure.
constexpr int kUninitializedIndex = -1;

// Requests an external index from OpenSSL for the index type `index_type`.
// Valid index types are the `CRYPTO_EX_INDEX_*` constants found in OpenSSL's
// crypto.h header.
//
// Returns the external index on success or -1 on failure.
inline StatusOr<int> GetIndex(int index_type) {
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

}  // namespace

static int rsa_index = kUninitializedIndex;
static int engine_index = kUninitializedIndex;

Status InitExternalIndicies() {
  KMSENGINE_ASSIGN_OR_RETURN(rsa_index, GetIndex(CRYPTO_EX_INDEX_RSA));
  KMSENGINE_ASSIGN_OR_RETURN(engine_index, GetIndex(CRYPTO_EX_INDEX_ENGINE));
  return {};
}

void FreeExternalIndicies() {
  CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, rsa_index);
  CRYPTO_free_ex_index(CRYPTO_EX_INDEX_ENGINE, engine_index);
}

Status AttachRsaKeyToOpenSslRsa(backing::RsaKey *rsa_key, RSA *rsa) {
  if (rsa_index == kUninitializedIndex) {
    return Status(Status::kFailedPrecondition, "rsa_index uninitialized");
  }

  if (!RSA_set_ex_data(rsa, rsa_index, static_cast<void *>(rsa_key))) {
    return Status(StatusCode::kInternal, "RSA_set_ex_data failed");
  }
  return {};
}

StatusOr<backing::RsaKey *> GetRsaKeyFromOpenSslRsa(const RSA *rsa) {
  if (rsa_index == kUninitializedIndex) {
    return Status(StatusCode::kFailedPrecondition, "rsa_index uninitialized");
  }

  auto ex_data = RSA_get_ex_data(rsa, rsa_index);
  if (ex_data == nullptr) {
    return Status(StatusCode::kNotFound,
                  "No Cloud KMS key associated with RSA struct");
  }
  return static_cast<backing::RsaKey *>(ex_data);
}

Status AttachClientToOpenSslEngine(backing::Client *client, ENGINE *engine) {
  if (engine_index == kUninitializedIndex) {
    return Status(StatusCode::kFailedPrecondition,
                  "engine_index uninitialized");
  }

  if (!ENGINE_set_ex_data(engine, engine_index, static_cast<void *>(client))) {
    return Status(StatusCode::kInternal, "ENGINE_set_ex_data failed");
  }
  return {};
}

StatusOr<backing::Client *> GetClientFromOpenSslEngine(const ENGINE *engine) {
  if (engine_index == kUninitializedIndex) {
    return Status(StatusCode::kFailedPrecondition,
                  "engine_index uninitialized");
  }

  auto ex_data = ENGINE_get_ex_data(engine, engine_index);
  if (ex_data == nullptr) {
    return Status(StatusCode::kNotFound,
                  "No Cloud KMS Client associated with ENGINE struct");
  }
  return static_cast<backing::Client *>(ex_data);
}

}  // namespace bridge
}  // namespace kmsengine
