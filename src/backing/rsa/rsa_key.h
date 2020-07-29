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

#ifndef KMSENGINE_BACKING_RSA_RSA_KEY_H_
#define KMSENGINE_BACKING_RSA_RSA_KEY_H_

#include <string>

#include "src/backing/base_macros.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {

// Interface representing a RSA private key.
//
// When `RSA` objects are generated by the engine, an `RsaKey` implementation
// containing a handle to the private key resource ID should be attached to the
// `RSA` object. Then, when the bridge layer's `RSA_METHOD` implementations are
// called, the bridge layer should retrieve the `RsaKey` attached to the calling
// `RSA` object.
//
// The bridge layer is also responsible for converting OpenSSL-native types from
// the `RSA_METHOD` arguments into engine-native types prior to calling the
// associated `RsaKey` methods. This is because some conversions require
// knowledge of symbols from the OpenSSL library (which is not available to the
// backing layer).
class BRIDGE_EXPORT RsaKey {
 public:
  BRIDGE_EXPORT virtual ~RsaKey() = default;

  // Signs `message_digest` using the underlying RSA private key. Returns the
  // resulting signature as a `std::string`, or an error `Status`.
  //
  // Should be used in the engine's implementation of `RSA_sign`.
  BRIDGE_EXPORT virtual StatusOr<std::string> Sign(DigestCase type,
                                     std::string message_digest) = 0;

  // Returns the PEM-encoded public key of the underlying RSA private key, or
  // an error `Status`.
  //
  // Should be used in the engine's implementation of `RSA_verify`.
  //
  // Unlike how `RsaKey`'s `Sign` method performs all of the signing work,
  // actual public key verification needs to happen in the bridge layer instead
  // since verification needs to be implemented with OpenSSL functions that are
  // only available to the bridge layer.
  BRIDGE_EXPORT virtual StatusOr<PublicKey> GetPublicKey() = 0;
};

}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_RSA_RSA_KEY_H_
