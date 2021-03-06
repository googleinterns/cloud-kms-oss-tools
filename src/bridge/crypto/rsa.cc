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
#include "src/backing/status/status_or.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/bridge/nid_util/nid_util.h"

namespace kmsengine {
namespace bridge {
namespace crypto {
namespace {

using ::kmsengine::backing::CryptoKeyHandle;
using ::kmsengine::backing::DigestCase;

// A human-readable name associated with the Cloud KMS engine's RSA_METHOD.
//
// Used by some OpenSSL-backed applications.
static constexpr char kRsaMethodName[] = "Google Cloud KMS RSA Method";

// Bitwise mask of OpenSSL flags to associate with the Cloud KMS engine's
// RSA_METHOD. See `rsa.h` from OpenSSL for flag definitions.
//
// The flags that are currently set are:
//
//  - RSA_FLAG_EXT_PKEY: This flag means that the private key material
//    normally stored within an OpenSSL RSA struct does not exist. Our
//    engine operates on Cloud KMS keys, so this flag is set. See
//    RSA_new_method(3) for more information.
//
//  - RSA_METHOD_FLAG_NO_CHECK: Tells OpenSSL that the key material stored in
//    the RSA struct may not contain both private and public key information
//    (this is the case due to the fact that the engine does not have access to
//    Cloud KMS private key material) and thus it should not check that the
//    private and public key form a valid pair.
//
//    RSA_new_method(3) documents the existence of the RSA_METHOD_FLAG_NO_CHECK
//    flag, but see https://github.com/openssl/openssl/pull/2243 for a more
//    detailed explanation.
//
static constexpr int kRsaMethodFlags = RSA_FLAG_EXT_PKEY |
                                       RSA_METHOD_FLAG_NO_CHECK;

// Wrapper around error-checking and `reinterpret_cast` to make a std::string
// representing a digest passed from OpenSSL as an unsigned char pointer and
// length.
StatusOr<std::string> MakeDigestString(const unsigned char *m,
                                       const unsigned int m_length) {
  if (m == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Message digest pointer cannot be null");
  }
  if (m_length == 0) {
    return Status(StatusCode::kInvalidArgument,
                  "Message digest length cannot be zero");
  }

  return std::string(reinterpret_cast<const char *>(m), m_length);
}

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
  return 1;
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
      GetCryptoKeyHandleFromOpenSslRsa(rsa), 0);
  delete crypto_key_handle;

  KMSENGINE_RETURN_IF_OPENSSL_ERROR(
      AttachCryptoKeyHandleToOpenSslRsa(nullptr, rsa), 0);
  return 1;
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
  // Sanity check on `RSA_size` and the length of the signature.
  int rsa_size = RSA_size(rsa);
  if (RSA_size(rsa) < 0) {
    KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kFailedPrecondition,
                                  "RSA_size(rsa) was < 0"));
    return 0;
  }

  // We populate `signature_length` with an initial "max length" that the
  // signature could be (which is `RSA_size(rsa)`) so the caller knows how much
  // memory to allocate for `signature_return`, if they haven't done so already.
  if (signature_length == nullptr) {
    KMSENGINE_SIGNAL_ERROR(
        Status(StatusCode::kInvalidArgument,
               "Signature length parameter may not be null"));
    return 0;
  }
  *signature_length = rsa_size;

  // If `signature_return` is defined, then we actually perform the signing
  // operation.
  if (signature_return != nullptr) {
    // Convert arguments to engine-native structures for convenience. These
    // conversions need to take place within the bridge layer (as opposed to
    // letting the `RsaKey::Sign` method handling the conversions) since the
    // conversion functions refer to some OpenSSL API functions.
    KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
        const CryptoKeyHandle *crypto_key_handle,
        GetCryptoKeyHandleFromOpenSslRsa(rsa), 0);
    KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
        const DigestCase digest_type,
        ConvertOpenSslNidToDigestType(type), 0);
    KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
        const std::string digest_string,
        MakeDigestString(digest_bytes, digest_length), 0);

    // Delegate handling of the signing operation to the backing layer.
    KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
        const std::string signature,
        crypto_key_handle->Sign(digest_type, digest_string), 0);

    if (signature.length() > static_cast<std::string::size_type>(rsa_size)) {
      KMSENGINE_SIGNAL_ERROR(
          Status(StatusCode::kFailedPrecondition,
                 "Generated signature length was unexpectedly larger than "
                 "RSA_size(rsa)"));
      return 0;
    }

    // Copy resulting signature into result pointers and update
    // `signature_length` if needed.
    signature.copy(reinterpret_cast<char *>(signature_return),
                   signature.length());
    *signature_length = signature.length();
  }

  return 1;
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
  // be implemented at some point in the future. The OpenSSL CLI seems to use
  // RSA_public_decrypt over RSA_verify, so this never really gets called at the
  // moment.
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return 0;
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

StatusOr<OpenSslRsaMethod> MakeKmsRsaMethod() {
  OpenSslRsaMethod rsa_method = MakeRsaMethod(kRsaMethodName, kRsaMethodFlags);
  if (rsa_method == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
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
      !RSA_meth_set_init(rsa_method.get(), Init) ||
      !RSA_meth_set_finish(rsa_method.get(), Finish) ||
      // `mod_exp` and `bn_mod_exp` are called by the default OpenSSL RSA
      // method. The OpenSSL man page for RSA_set_method(3) explicitly
      // permits these callbacks to be set to null in an engine implementation.
      // However, we are defining them here to be the OpenSSL defaults since
      // the OpenSSL command-line utilities apparently use them for verification
      // operations.
      !RSA_meth_set_mod_exp(rsa_method.get(),
                            RSA_meth_get_mod_exp(openssl_rsa_method)) ||
      !RSA_meth_set_bn_mod_exp(rsa_method.get(),
                               RSA_meth_get_bn_mod_exp(openssl_rsa_method)) ||
      // `keygen` is NULL since key management functions are out of scope of
      // the Cloud KMS engine. The OpenSSL man page for RSA_set_method(3)
      // explicitly permits this callback to be set to null in an engine
      // implementation.
      !RSA_meth_set_keygen(rsa_method.get(), nullptr)) {
    return Status(StatusCode::kInternal, "RSA_meth_set_* failed");
  }

  return rsa_method;
}

}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine
