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

#include <memory>

#include <openssl/engine.h>
#include <openssl/rsa.h>

namespace kmsengine {
namespace bridge {
namespace memory_util {

// This file exposes smart pointer wrappers around various OpenSSL structs.
// They should be used when all of the following conditions are met:
//
//    - The engine needs to instantiate a new OpenSSL struct.
//    - The engine is responsible for owning the instance of that struct.
//    - The engine is responsible for cleaning up the struct instance.
//
// Existing OpenSSL struct pointers passed from OpenSSL applications should not
// be converted to smart pointers since the engine does not "own" that
// pointer.

// Smart pointer wrapper around OpenSSL's RSA struct. Just an alias for
// convenience.
using OpenSSLRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;

// Smart pointer wrapper around OpenSSL's RSA_METHOD struct. Just an alias for
// convenience.
using OpenSSLRsaMethod = std::unique_ptr<RSA_METHOD, decltype(&RSA_meth_free)>;

// Constructs a `std::unique_ptr` object which owns a fresh RSA instance.
// May return `nullptr` if no memory is available.
//
// The OpenSSL `RSA_free` function is automatically called to dispose
// of the underlying RSA instance when the pointer goes out of scope.
inline OpenSSLRsa MakeRsa() {
  return OpenSSLRsa(RSA_new(), &RSA_free);
}

// Constructs a `std::unique_ptr` object which owns a fresh RSA_METHOD instance.
// May return `nullptr` if no memory is available.
//
// The OpenSSL `RSA_meth_free` function is automatically called to dispose
// of the underlying RSA_METHOD instance when the pointer goes out of scope.
inline OpenSSLRsaMethod MakeRsaMethod(const char *name, int flags) {
  return OpenSSLRsaMethod(RSA_meth_new(name, flags), &RSA_meth_free);
}

}  // namespace memory_util
}  // namespace bridge
}  // namespace kmsengine
