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

#include "src/bridge/rsa/rsa_method.h"

#include <openssl/rsa.h>

#include "src/bridge/rsa/rsa.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace rsa {

OpenSslRsaMethod MakeKmsRsaMethod() {
  // RSA_FLAG_EXT_PKEY identifies that the RSA key is stored in external
  // hardware.
  auto rsa_method = MakeRsaMethod(kRsaMethodName, kRsaMethodFlags);
  if (!rsa_method) return OpenSslRsaMethod(nullptr, nullptr);

  if (!RSA_meth_set_pub_enc(rsa_method.get(), PublicEncrypt) ||
      !RSA_meth_set_pub_dec(rsa_method.get(), PublicDecrypt) ||
      !RSA_meth_set_priv_enc(rsa_method.get(), PrivateEncrypt) ||
      !RSA_meth_set_priv_dec(rsa_method.get(), PrivateDecrypt) ||
      !RSA_meth_set_sign(rsa_method.get(), Sign) ||
      !RSA_meth_set_verify(rsa_method.get(), Verify) ||
      // `mod_exp` and `bn_mod_exp` are called by the default OpenSSL RSA
      // method. They are NULL since we're overriding the default RSA
      // methods anyways.
      !RSA_meth_set_mod_exp(rsa_method.get(), nullptr) ||
      !RSA_meth_set_bn_mod_exp(rsa_method.get(), nullptr) ||
      // `keygen` is NULL since key management functions are out of scope of
      // the Cloud KMS engine.
      !RSA_meth_set_keygen(rsa_method.get(), nullptr) ||
      // `init` is called in response to the OpenSSL application calling
      // `RSA_new`. Initialization work is delegated to the EVP_PKEY loader, so
      // it is NULL.
      !RSA_meth_set_init(rsa_method.get(), nullptr) ||
      !RSA_meth_set_finish(rsa_method.get(), Finish)) {
    return OpenSslRsaMethod(nullptr, nullptr);
  }

  return rsa_method;
}

}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
