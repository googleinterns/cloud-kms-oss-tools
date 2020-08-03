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

#ifndef KMSENGINE_BRIDGE_EX_DATA_UTIL_ENGINE_DATA_H_
#define KMSENGINE_BRIDGE_EX_DATA_UTIL_ENGINE_DATA_H_

#include <memory>
#include <string>

#include <openssl/rsa.h>

#include "src/backing/client/client.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {

// Container for structures that need to be referred to across OpenSSL engine
// calls.
//
// An instance of `EngineData` is attached to the OpenSSL `ENGINE` struct via
// OpenSSL's "ex_data" API. Then, when OpenSSL delegates calls to the engine
// implementation, our codebase can retrieve the native `EngineData` from the
// `ENGINE` struct passed from OpenSSL and then retrieve structures specific
// to our engine implementation.
class EngineData {
 public:
  EngineData(std::unique_ptr<backing::Client> client,
             OpenSslRsaMethod rsa_method,
             OpenSslEcKeyMethod ec_key_method)
      : client_(std::move(client)),
        rsa_method_(std::move(rsa_method)),
        ec_key_method_(std::move(ec_key_method)) {}

  // `EngineData` is not copyable or movable.
  EngineData(const EngineData&) = delete;
  EngineData& operator=(const EngineData&) = delete;

  // Returns a reference to the `backing::Client` associated with the
  // `EngineData`.
  backing::Client const& client() const { return *client_; }

  // Returns a raw pointer to the engine's `RSA_METHOD`.
  //
  // The return type is a raw pointer instead of a reference since the main
  // usage case for accessing the `RSA_METHOD` is to pass it to an OpenSSL API
  // function, and the OpenSSL API functions consume raw pointers.
  const RSA_METHOD *rsa_method() const { return rsa_method_.get(); }

  // Returns a raw pointer to the engine's `EC_KEY_METHOD`.
  //
  // The return type is a raw pointer instead of a reference since the main
  // usage case for accessing the `EC_KEY_METHOD` is to pass it to an OpenSSL
  // API function, and the OpenSSL API functions consume raw pointers.
  const EC_KEY_METHOD *ec_key_method() const { return ec_key_method_.get(); }

 private:
  const std::unique_ptr<backing::Client> client_;
  const OpenSslRsaMethod rsa_method_;
  const OpenSslEcKeyMethod ec_key_method_;
};

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_EX_DATA_UTIL_ENGINE_DATA_H_
