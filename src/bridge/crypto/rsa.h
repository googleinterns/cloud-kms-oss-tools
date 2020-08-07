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

#ifndef KMSENGINE_BRIDGE_RSA_RSA_METHOD_H_
#define KMSENGINE_BRIDGE_RSA_RSA_METHOD_H_

#include <memory>

#include <openssl/rsa.h>

#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace crypto {

// A human-readable name associated with the Cloud KMS engine's RSA_METHOD.
//
// Used by some OpenSSL-backed applications.
constexpr char kRsaMethodName[] = "Google Cloud KMS RSA Method";

// Bitwise mask of OpenSSL flags to associate with the Cloud KMS engine's
// RSA_METHOD. See `rsa.h` from OpenSSL for flag definitions.
//
// The flags that are currently set are:
//
//  - RSA_FLAG_EXT_PKEY: This flag means that the private key material
//    normally stored within an OpenSSL RSA struct does not exist. Our
//    engine operates on Cloud KMS keys, so this flag is set.
//
constexpr int kRsaMethodFlags = RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK;

// Allocates memory for and initializes an OpenSSL `RSA_METHOD` struct with
// pointers to the Cloud KMS engine RSA implementations.
OpenSslRsaMethod MakeKmsRsaMethod();

}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_RSA_RSA_METHOD_H_
