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

#ifndef KMSENGINE_BRIDGE_MEMORY_UTIL_OPENSSL_STRUCTS_H_
#define KMSENGINE_BRIDGE_MEMORY_UTIL_OPENSSL_STRUCTS_H_

#include <memory>

#include <openssl/engine.h>
#include <openssl/rsa.h>

namespace kmsengine {
namespace bridge {

// This file exposes smart pointer wrappers around various OpenSSL structs.
// They should be used when all of the following conditions are met:
//
//    - The engine needs to instantiate a new OpenSSL struct.
//
//    - The engine (not OpenSSL, or another OpenSSL struct) "owns" the instance
//      of that struct. (For example, while the engine is responsibile for
//      instantiating both an `EVP_PKEY` and an `RSA` instance in the key
//      loader, it should not use the smart pointer interface for the `RSA`
//      instance since the `RSA` instance is "owned" by the `EVP_PKEY`. The
//      `EVP_PKEY` should not be converted to a smart pointer as well since
//      ownership of the `EVP_PKEY` is passed back to the client application.)
//
//    - The engine is responsible for cleaning up the struct instance (for,
//      example, it doesn't pass ownership / cleanup responsibility of the
//      instance to OpenSSL via an API function, etc.).
//
// Existing OpenSSL struct pointers passed from OpenSSL applications should not
// be converted to smart pointers since the engine does not "own" that
// pointer.

// Smart pointer wrapper around OpenSSL's BIO struct. Just an alias for
// convenience.
using OpenSslBio = std::unique_ptr<BIO, decltype(&BIO_free)>;

// Smart pointer wrapper around OpenSSL's ENGINE struct. Just an alias for
// convenience.
using OpenSslEngine = std::unique_ptr<ENGINE, decltype(&ENGINE_free)>;

// Smart pointer wrapper around OpenSSL's EVP_PKEY struct. Just an alias for
// convenience.
using OpenSslEvpPkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

// Smart pointer wrapper around OpenSSL's RSA struct. Just an alias for
// convenience.
using OpenSslRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;

// Smart pointer wrapper around OpenSSL's RSA_METHOD struct. Just an alias for
// convenience.
using OpenSslRsaMethod = std::unique_ptr<RSA_METHOD, decltype(&RSA_meth_free)>;

// Constructs a `std::unique_ptr` object which owns a fresh ENGINE instance.
// May return `nullptr` if no memory is available.
//
// The OpenSSL `ENGINE_free` function is automatically called to dispose
// of the underlying ENGINE instance when the pointer goes out of scope.
inline OpenSslEngine MakeEngine() {
  return OpenSslEngine(ENGINE_new(), &ENGINE_free);
}

// Constructs a `std::unique_ptr` object which owns a fresh EVP_PKEY instance.
// May return `nullptr` if no memory is available.
//
// The OpenSSL `EVP_PKEY_free` function is automatically called to dispose
// of the underlying EVP_PKEY instance when the pointer goes out of scope.
inline OpenSslEvpPkey MakeEvpPkey() {
  return OpenSslEvpPkey(EVP_PKEY_new(), &EVP_PKEY_free);
}

// Constructs a `std::unique_ptr` object which owns a fresh RSA instance.
// May return `nullptr` if no memory is available.
//
// The OpenSSL `RSA_free` function is automatically called to dispose
// of the underlying RSA instance when the pointer goes out of scope.
inline OpenSslRsa MakeRsa() {
  return OpenSslRsa(RSA_new(), &RSA_free);
}

// Constructs a `std::unique_ptr` object which owns a fresh RSA_METHOD instance.
// May return `nullptr` if no memory is available.
//
// The OpenSSL `RSA_meth_free` function is automatically called to dispose
// of the underlying RSA_METHOD instance when the pointer goes out of scope.
inline OpenSslRsaMethod MakeRsaMethod(const char *name, int flags) {
  return OpenSslRsaMethod(RSA_meth_new(name, flags), &RSA_meth_free);
}

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_MEMORY_UTIL_OPENSSL_STRUCTS_H_
