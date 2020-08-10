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

#include "src/bridge/crypto/rsa.h"

#include <openssl/rsa.h>

#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace crypto {
namespace {

using ::kmsengine::CryptoKeyHandle;
using ::kmsengine::DigestCase;

// Called when OpenSSL's `RSA_new_method` is called to initialize a new
// `RSA` struct using the Cloud KMS engine.
//
// This is a no-op, as the key loader function is responsible for initializing
// RSA structs to have meaningful engine-specific data. While some engine
// implementations set the `init` callback to a null pointer, the OpenSSL
// specification does not explicitly permit this function to be null in an
// engine's `RSA_METHOD` implementation, so we define it as a no-op here.
//
// Returns 1 on success; otherwise, returns 0.
int Init(RSA *rsa) {
  return true;
}

// Cleans up any internal structures associated with the input `rsa` struct
// (except for the RSA struct itself, which will be cleaned up by the OpenSSL
// library).
//
// Called when OpenSSL's `RSA_free` is called on `rsa`. (See the OpenSSL man
// page for RSA_free(3) for more information.)
//
// Returns 1 on success; otherwise, returns 0.
int Finish(RSA *rsa) {
  // `crypto_key_handle` is guaranteed to be non-null here (if the underlying
  // external data struct was null, an error status would be returned).
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      const CryptoKeyHandle *crypto_key_handle,
      GetCryptoKeyHandleFromOpenSslRsa(rsa), false);
  delete crypto_key_handle;

  Status status = AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa);
  if (!status.ok()) {
    KMSENGINE_SIGNAL_ERROR(status);
  }
  return status.ok();
}

// Signs the message digest `digest_bytes` of length `digest_length` using the
// RSA private key represented by the OpenSSL RSA struct `rsa`. Then, stores the
// resulting signature in `signature_return` and the signature size in
// `signature_length`. The caller is responsible for ensuring that
// `signature_return` points to `RSA_size(rsa)` bytes of memory. (See the
// OpenSSL man page for RSA_sign(3) for more information.)
//
// Returns 1 on success; otherwise, returns 0.
//
// The function signature comes from the prototype for `RSA_meth_set_sign` from
// the OpenSSL API.
int Sign(int type, const unsigned char *digest_bytes,
         unsigned int digest_length, unsigned char *signature_return,
         unsigned int *signature_length, const RSA *rsa) {
  // Convert arguments to engine-native structures for convenience. These
  // conversions need to take place within the bridge layer (as opposed to
  // letting the `RsaKey::Sign` method handling the conversions) since the
  // conversion functions refer to some OpenSSL API functions.
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      const CryptoKeyHandle *crypto_key_handle,
      GetCryptoKeyHandleFromEcKey(ec_key), false);
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      const DigestCase digest_type,
      ConvertOpenSslNidToDigestType(type), false);
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      const std::string digest_string,
      MakeDigestString(digest_bytes, digest_length), false);

  // Delegate handling of the signing operation to the backing layer.
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      const std::string signature,
      crypto_key_handle->Sign(digest_type, digest_string), false);

  // Copy results into the return pointers.
  if (signature_return != nullptr) {
    signature.copy(reinterpret_cast<char *>(signature_return),
                   signature.length());
  }
  if (signature_length != nullptr) {
    *signature_length = signature.length();
  }
  return true;
}

// Verifies that the signature `sigbuf` of size `siglen` matches the given
// message digest `m` of size `m_len`. `type` denotes the message digest
// algorithm that was used to generate the signature. `rsa` is the signer's
// public key.
//
// Returns 1 on success; otherwise, returns 0.
//
// The function signature comes from the prototype for `RSA_meth_set_verify`
// from the OpenSSL API.
int Verify(int type, const unsigned char *m, unsigned int m_len,
           const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa) {
  // TODO(https://github.com/googleinterns/cloud-kms-oss-tools/issues/101):
  // This method is currently purposely left unimplemented, but it may need to
  // be implemented at some point in the future.
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return false;
}

// Signs the `from_length` bytes in `from` using the RSA key `rsa` and stores
// the signature in `to`. The caller is responsible for ensuring that `to`
// points to `RSA_size(rsa)` bytes of memory. (See the OpenSSL man page for
// RSA_private_encrypt(3) for more information.)
//
// According to the OpenSSL specification, `from` is usually a message
// digest, but it doesn't have to be.
//
// Returns the length of `to` on success; otherwise, returns -1.
//
// The function signature comes from the prototype for `RSA_meth_set_priv_enc`
// from the OpenSSL API.
int PrivateEncrypt(int from_length, const unsigned char *from,
                   unsigned char *to, RSA *rsa, int padding) {
  // TODO(https://github.com/googleinterns/cloud-kms-oss-tools/issues/100): It
  // may or may not be possible to simply redirect `PrivateEncrypt` to `Sign`.
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return -1;
}

// Recovers the message digest from the `from_length` bytes long signature in
// `from` using the RSA key `rsa`. The caller is responsible for ensuring that
// `to` points to a memory section large enough to hold the message digest
// (which is smaller than `RSA_size(rsa) - 11`). `padding` is the padding mode
// that was used to sign the data. (See the OpenSSL man page for
// RSA_private_decrypt(3) for more information.)
//
// Returns the length of `to` on success; otherwise, returns -1.
//
// The function signature comes from the prototype for `RSA_meth_set_priv_dec`
// from the OpenSSL API.
int PrivateDecrypt(int from_length, const unsigned char *from,
                   unsigned char *to, RSA *rsa, int padding) {
  // TODO(https://github.com/googleinterns/cloud-kms-oss-tools/issues/102):
  // Currently unimplemented on purpose, but can be defined when keys with the
  // `ASYMMETRIC_DECRYPT` purpose should be supported by the engine.
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return -1;
}

}  // namespace

OpenSslRsaMethod MakeKmsRsaMethod() {
  OpenSslRsaMethod rsa_method = MakeRsaMethod(kRsaMethodName, kRsaMethodFlags);
  if (rsa_method == nullptr) {
    return OpenSslRsaMethod(nullptr, nullptr);
  }

  // `RSA_PKCS1_OpenSSL` returns the default OpenSSL `RSA_METHOD`
  // implementation. We use it to "borrow" default implementations for public
  // key-related operations, since the way those work should not change given
  // that the engine has access to public key material.
  const RSA_METHOD *openssl_rsa_method = RSA_PKCS1_OpenSSL();
  if (// Public key operations can just reuse the OpenSSL defaults. This works
      // because the engine key loader initializes `RSA` structs with all of
      // the necessary public key material.
      !RSA_meth_set_pub_enc(rsa_method.get(),
                            RSA_meth_get_pub_enc(openssl_rsa_method)) ||
      !RSA_meth_set_pub_dec(rsa_method.get(),
                            RSA_meth_get_pub_dec(openssl_rsa_method)) ||
      // There is no OpenSSL default for `verify`, so we need to implement it
      // ourselves.
      !RSA_meth_set_verify(rsa_method.get(), Verify) ||
      // Private key operations need to be implemented by our engine.
      !RSA_meth_set_priv_dec(rsa_method.get(), PrivateDecrypt) ||
      !RSA_meth_set_priv_enc(rsa_method.get(), PrivateEncrypt) ||
      !RSA_meth_set_sign(rsa_method.get(), Sign) ||
      // Memory initialization and cleanup functions.
      !RSA_meth_set_init(rsa_method.get(), RsaInit) ||
      !RSA_meth_set_finish(rsa_method.get(), Finish) ||
      // `mod_exp` and `bn_mod_exp` are called by the default OpenSSL RSA
      // method. The OpenSSL man page for RSA_set_method(3) explicitly
      // permits these callbacks to be set to null in an engine implementation.
      // However, we are defining them here to be the OpenSSL defaults since
      // the OpenSSL command-line utilities apparently require them to be
      // defined in order for verification operations to work.
      !RSA_meth_set_mod_exp(rsa_method.get(),
                            RSA_meth_get_mod_exp(openssl_rsa_method)) ||
      !RSA_meth_set_bn_mod_exp(rsa_method.get(),
                               RSA_meth_get_bn_mod_exp(openssl_rsa_method)) ||
      // `keygen` is NULL since key management functions are out of scope of
      // the Cloud KMS engine. The OpenSSL man page for RSA_set_method(3)
      // explicitly permits this callback to be set to null in an engine
      // implementation.
      !RSA_meth_set_keygen(rsa_method.get(), nullptr)) {
    return OpenSslRsaMethod(nullptr, nullptr);
  }

  return rsa_method;
}

}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine
