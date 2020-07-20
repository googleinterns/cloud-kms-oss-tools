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

#ifndef KMSENGINE_BRIDGE_EX_DATA_UTIL_EX_DATA_UTIL_H_
#define KMSENGINE_BRIDGE_EX_DATA_UTIL_EX_DATA_UTIL_H_

#include <memory>

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "src/backing/rsa/rsa_key.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/engine_data.h"

namespace kmsengine {
namespace bridge {

// Attempts to request ex_data indices from OpenSSL, and, if successful,
// returns a success `Status`.
//
// The optional `service` parameter is for testing purposes.
Status InitExternalIndicies();

// Frees the ex_data indicies requested from OpenSSL.
void FreeExternalIndicies();

// Attaches an `RsaKey` instance to the OpenSSL `RSA` instance.
Status AttachRsaKeyToOpenSslRsa(backing::RsaKey *rsa_key, RSA *rsa);

// Returns a raw pointer to the `RsaKey` instance attacked to the given
// OpenSSL `RSA` struct. Raw pointer will never be null (if the underlying
// external data is null, then an error status is returned.)
//
// Attached data is only defined by a previous call to `AttachRsaKeyToRSA`.
StatusOr<backing::RsaKey *> GetRsaKeyFromOpenSslRsa(const RSA *rsa);

// Attaches an `Client` instance to the OpenSSL `RSA` instance.
Status AttachEngineDataToOpenSslEngine(EngineData *client, ENGINE *engine);

// Returns a raw pointer to the `EngineData` instance attacked to the given
// OpenSSL `ENGINE` struct, or an error status. Raw pointer will never be null
// (if the underlying external data is null, then an error status is returned.)
//
// Attached data is only defined by a previous call to `AttachClientToENGINE`.
StatusOr<EngineData *> GetEngineDataFromOpenSslEngine(const ENGINE *engine);

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_EX_DATA_UTIL_EX_DATA_UTIL_H_