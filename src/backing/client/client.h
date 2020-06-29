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

#ifndef KMSENGINE_BACKING_CLIENT_CLIENT_H_
#define KMSENGINE_BACKING_CLIENT_CLIENT_H_

#include "src/backing/client/asymmetric_sign_request.h"
#include "src/backing/client/asymmetric_sign_response.h"

namespace kmsengine {
namespace backing {
namespace client {

// Defines the interface used to communicate with the Google Cloud KMS API.
class Client {
 public:
  virtual ~Client() = 0;

  // Signs data using the CryptoKeyVersion with name
  // `AsymmetricSignRequest::KeyName()`. Produces a signature that can be
  // verified with the public key retrieved from `GetPublicKey`.
  //
  // The CryptoKeyVersion must have CryptoKey.purpose ASYMMETRIC_SIGN. If not,
  // an error status is returned.
  virtual StatusOr<AsymmetricSignResponse> AsymmetricSign(
      AsymmetricSignRequest const& request) = 0;
};

}  // namespace client
}  // namespace backing
}  // namespace kmsengine

#endif  // KMSENGINE_BACKING_CLIENT_CLIENT_H_
