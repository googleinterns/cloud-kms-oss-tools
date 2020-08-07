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

#include "src/bridge/crypto/ec.h"

#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace rsa {
namespace {

int Init(EC_KEY *key) {
  return 0;
}

int Finish(EC_KEY *key) {
  return 0;
}

int Copy(EC_KEY *dest, const EC_KEY *src) {
  return 0;
}

int SetGroup(EC_KEY *key, const EC_GROUP *grp) {
  return 0;
}

int SetPrivate(EC_KEY *key, const BIGNUM *priv_key) {
  return 0;
}

int SetPublic(EC_KEY *key, const EC_POINT *pub_key) {
  return 0;
}

int SignEx(int type, const unsigned char *dgst, int dgstlen,
           unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
           const BIGNUM *r, EC_KEY *eckey) {
  return 0;
}

int SignSetup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **rp) {
  return 0;
}

ECDSA_SIG *DoSignEx(const unsigned char *dgst, int dgstlen,
                         const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey) {
  return 0;
}

int Verify(int type, const unsigned char *dgst, int dgst_len,
           const unsigned char *sigbuf, int sig_len, EC_KEY *eckey) {
  return -1;
}

int DoVerify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey) {
  return -1;
}

int GenerateKey(EC_KEY *key) {
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return 0;
}

int ComputeKey(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
               void *(*KDF) (const void *in, size_t inlen, void *out,
                             size_t *outlen)) {
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return -1;
}

}  // namespace

OpenSslEcKeyMethod MakeKmsEcKeyMethod() {
  // `EC_KEY_OpenSSL` returns the default OpenSSL `RSA_METHOD`
  // implementation. We use it to "borrow" default implementations for public
  // key-related operations, since the way those work should not change given
  // that the engine has access to public key material.
  const EC_KEY_METHOD *default_ec_key_method = EC_KEY_OpenSSL();

  // `MakeEcKeyMethod` performs a shallow copy of the given `EC_KEY_METHOD`.
  OpenSslEcKeyMethod ec_key_method = MakeEcKeyMethod(default_ec_key_method);
  if (ec_key_method == nullptr) {
    return OpenSslEcKeyMethod(nullptr, nullptr);
  }

  if (// `EC_KEY_METHOD_set_init` sets multiple callback functions that are used
      // for `EC_KEY`-related memory management.
      //
      // See https://man.openbsd.org/EC_KEY_METHOD_new.3#EC_KEY_METHOD_set_init
      // for explanations of each callback and where the callbacks are called.
      !EC_KEY_METHOD_set_init(ec_key_method.get(), Init, Finish, Copy,
                              SetGroup, SetPrivate, SetPublic) ||
      // `EC_KEY_METHOD_set_sign` consumes three functions: the first function
      // is the implementation for `ECDSA_sign_ex`, the second function is for
      // `ECDSA_sign_setup`, and the third function is for `ECDSA_do_sign_ex`.
      !EC_KEY_METHOD_set_sign(ec_key_method.get(),
                              SignEx, SignSetup, DoSignEx) ||
      // `EC_KEY_METHOD_set_verify` consumes two functions: the first function
      // is the implementation for `ECDSA_verify` and the second function is the
      // implementation for `ECDSA_do_verify`.
      !EC_KEY_METHOD_set_verify(ec_key_method.get(), Verify, DoVerify) ||
      // `EC_KEY_METHOD_set_keygen` sets the function that implements
      // `EC_KEY_generate_key`.
      !EC_KEY_METHOD_set_keygen(ec_key_method.get(), GenerateKey) ||
      // `EC_KEY_METHOD_set_compute_key` sets the function that implements
      // `ECDH_compute_key`.
      !EC_KEY_METHOD_set_compute_key(ec_key_method.get(), ComputeKey)) {
    return OpenSslEcKeyMethod(nullptr, nullptr);
  }

  return ec_key_method;
}

}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine
