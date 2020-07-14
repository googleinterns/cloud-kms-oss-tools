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

#ifndef KMSENGINE_BRIDGE_RSA_RSA_H_
#define KMSENGINE_BRIDGE_RSA_RSA_H_

#include <openssl/rsa.h>

namespace kmsengine {
namespace bridge {
namespace rsa {

// Parameter names for `RSA_METHOD` functions are copied from the
// OpenSSL documentation and header files.

// Cleans up any internal structures associated with the input `rsa` struct
// (except for the RSA struct itself, which will be cleaned up by the OpenSSL
// library).
//
// Called when OpenSSL's `RSA_free` is called on `rsa`.
int Finish(RSA *rsa);

// TODO(zesp): Investigate if these are necessary given Sign and Verify.
int PublicEncrypt(int flen, const unsigned char *from, unsigned char *to,
                  RSA *rsa, int padding);
int PublicDecrypt(int flen, const unsigned char *from, unsigned char *to,
                  RSA *rsa, int padding);
int PrivateEncrypt(int flen, const unsigned char *from, unsigned char *to,
                   RSA *rsa, int padding);
int PrivateDecrypt(int flen, const unsigned char *from, unsigned char *to,
                   RSA *rsa, int padding);

// Signs the message digest `m` of length `m_length` using the RSA private key
// represented by the OpenSSL RSA struct `rsa`. Then, stores the resulting
// signature in `sigret` and the signature size in `siglen`. `sigret`
// points to `RSA_size(rsa)` bytes of memory.
//
// Returns 1 on success; otherwise, returns 0.
int Sign(int type, const unsigned char *m, unsigned int m_length,
         unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

// Verifies that the signature `sigbuf` of size `siglen` matches a given
// message digest `m` of size `m_len`. `type` denotes the message digest
// algorithm that was used to generate the signature. `rsa` is the signer's
// public key represented with the OpenSSL RSA struct.
//
// Returns 1 if the signature is successfully verified; otherwise, returns 0.
int Verify(int type, const unsigned char *m, unsigned int m_length,
           const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);

}  // namespace rsa
}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_RSA_RSA_H_
