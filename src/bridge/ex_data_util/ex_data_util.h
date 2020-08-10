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

#include <openssl/engine.h>
#include <openssl/rsa.h>

#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/ex_data_util/engine_data.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {

// Attempts to request ex_data indices from OpenSSL, and, if successful,
// returns a success `Status`.
//
// This function must be called before any of the `Attach*` or `Get*` functions
// are called. Callers of `InitExternalIndices` should then call
// `FreeExternalIndices` to release the ex_data indices back to OpenSSL after
// they have finished using them to avoid memory leaks.
Status InitExternalIndices();

// Frees the ex_data indices requested from OpenSSL.
void FreeExternalIndices();

// Attaches an `CryptoKeyHandle` instance to the OpenSSL `RSA` instance. Returns
// an error `Status` if an error occurred.
//
// `crypto_key_handle` may be null (for example, to reset attached data when
// freeing a previously-attached `CryptoKeyHandle` to avoid use-after-free
// errors). `rsa` may not be null.
//
// When possible, use the `unique_ptr` version to make ownership semantics
// clearer and to simplify cleanup in error cases.
Status AttachCryptoKeyHandleToOpenSslRsa(
    backing::CryptoKeyHandle *crypto_key_handle, RSA *rsa);
Status AttachCryptoKeyHandleToOpenSslRsa(
    std::unique_ptr<backing::CryptoKeyHandle> crypto_key_handle, RSA *rsa);

// Returns a raw pointer to the `CryptoKeyHandle` instance attached to the given
// OpenSSL `RSA` struct. Raw pointer will never be null (if the underlying
// external data is null, then an error `Status` is returned.)
//
// Attached data is only defined by a previous call to
// `AttachCryptoKeyHandleToOpenSslRsa`. `rsa` may not be null.
StatusOr<backing::CryptoKeyHandle *> GetCryptoKeyHandleFromOpenSslRsa(
    const RSA *rsa);

// Attaches an `CryptoKeyHandle` instance to the OpenSSL `EC_KEY` instance.
// Returns an error `Status` if an error occurred.
//
// `crypto_key_handle` may be null (for example, to reset attached data when
// freeing a previously-attached `CryptoKeyHandle` to avoid use-after-free
// errors). `ec_key` may not be null.
//
// When possible, use the `unique_ptr` version to make ownership semantics
// clearer and to simplify cleanup in error cases.
Status AttachCryptoKeyHandleToOpenSslEcKey(
    backing::CryptoKeyHandle *crypto_key_handle, EC_KEY *ec_key);
Status AttachCryptoKeyHandleToOpenSslEcKey(
    std::unique_ptr<backing::CryptoKeyHandle> crypto_key_handle,
    EC_KEY *ec_key);

// Returns a raw pointer to the `CryptoKeyHandle` instance attached to the given
// OpenSSL `EC_KEY` struct. Raw pointer will never be null (if the underlying
// external data is null, then an error `Status` is returned.)
//
// Attached data is only defined by a previous call to
// `AttachCryptoKeyHandleToOpenSslEcKey`. `ec_key` may not be null.
StatusOr<backing::CryptoKeyHandle *> GetCryptoKeyHandleFromOpenSslEcKey(
    const EC_KEY *ec_key);

// Attaches an `Client` instance to the OpenSSL `RSA` instance. Returns an
// error `Status` if an error occurred.
//
// `data` may be null (for example, to reset attached data when freeing a
// previously-attached `EngineData` to avoid use-after-free errors). `engine`
// may not be null.
Status AttachEngineDataToOpenSslEngine(EngineData *data, ENGINE *engine);

// Returns a raw pointer to the `EngineData` instance attacked to the given
// OpenSSL `ENGINE` struct, or an error status. Raw pointer will never be null
// (if the underlying external data is null, then an error `Status` is
// returned.)
//
// Attached data is only defined by a previous call to `AttachClientToENGINE`.
// `engine` may not be null.
StatusOr<EngineData *> GetEngineDataFromOpenSslEngine(const ENGINE *engine);

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_EX_DATA_UTIL_EX_DATA_UTIL_H_
