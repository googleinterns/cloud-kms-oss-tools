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

#include "engine/engine.h"

#include "openssl/engine.h"
#include "engine/rand.h"

namespace engine {

class KeyLoader {
public:
  static EVP_PKEY *LoadPrivkey(
      ENGINE *ossl_engine,
      const char *key_id,
      I_METHOD *ui_method,
      void *callback_data) {

    // Register some new application-specific data.
    // We may want to look into the free ptrs etc.
    // https://www.openssl.org/docs/man1.0.2/man3/RSA_get_ex_new_index.html.
    // If you pass a new_ptr it will be called when RSA_new_method is called,
    // so application-specific data will be initialized right then.
    // For some reason other applications do not use this though.
    // not sure why.
    int hsm_rsa_key_index = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);


    RSA *rsa_key = RSA_new_method(ossl_engine);
    if (!rsa_key) {
      // malloc failed.
    }

    // char *ex_ptr = OPENSSL_malloc(234234);
    // RSA_set_ex_data(rsa_key, hsm_rsa_key_index, ex_ptr);
    RSA_set_flags(rsa_key, RSA_FLAG_EXT_PKEY);  // Signals that this is an "external" private key type (i.e. engine specified)

    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    if (!evp_pkey) {
      RSA_free(rsa_key);
      // malloc failed.
    }

    EVP_PKEY_assign_RSA(evp_pkey, rsa_key);


  // EVP_PKEY_set1_engine
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_type.html
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_new.html
  }

  static int RsaFinish(RSA* rsa) {
    //     HWCryptoHook_RSAKeyHandle *hptr;

    // hptr = RSA_get_ex_data(rsa, hndidx_rsa);
    // if (hptr) {
    //     p_hwcrhk_RSAUnloadKey(*hptr, NULL);
    //     OPENSSL_free(hptr);
    //     RSA_set_ex_data(rsa, hndidx_rsa, NULL);
    // }
    // return 1;

  }


private:


}


}  // namespace engine


