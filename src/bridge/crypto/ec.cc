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

#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/nid_util/nid_util.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {
namespace crypto {
namespace {

using ::kmsengine::backing::CryptoKeyHandle;
using ::kmsengine::backing::DigestCase;

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

// Cleans up any internal structures associated with the input `ec_key` struct
// (except for the `EC_KEY` struct itself, which will be cleaned up by the
// OpenSSL library).
//
// Called when OpenSSL's `EC_KEY_free` is called on `ec_key`.
void Finish(EC_KEY *ec_key) {
  // `crypto_key_handle` is guaranteed to be non-null here (if the underlying
  // external data struct was null, an error status would be returned).
  StatusOr<CryptoKeyHandle *> crypto_key_handle_or =
      GetCryptoKeyHandleFromOpenSslEcKey(ec_key);
  if (crypto_key_handle_or.ok()) {
    delete crypto_key_handle_or.value();
  }

  Status status = AttachCryptoKeyHandleToOpenSslEcKey(nullptr, ec_key);
  if (!status.ok()) {
    KMSENGINE_SIGNAL_ERROR(status);
  }
}

// Called at the end of `EC_KEY_copy`, which copies the contents of `src` into
// `dest`.
//
// Returns 1 on success; otherwise, returns 0.
int Copy(EC_KEY *dest, const EC_KEY *src) {
  // `crypto_key_handle` is guaranteed to be non-null here (if the underlying
  // external data struct was null, an error status would be returned).
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      const CryptoKeyHandle *src_handle,
      GetCryptoKeyHandleFromOpenSslEcKey(src), 0);
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      std::unique_ptr<CryptoKeyHandle> dest_handle,
      backing::CopyCryptoKeyHandle(*src_handle), 0);

  Status status = AttachCryptoKeyHandleToOpenSslEcKey(
      std::move(dest_handle), dest);
  if (!status.ok()) {
    KMSENGINE_SIGNAL_ERROR(status);
    return 0;
  }
  return 1;
}

// Engine implementation for `ECDSA_sign_ex`.
//
// Computes a digital signature of the hash value `digest_bytes` of length
// `digest_length` using the private EC key `ec_key`.
//
// According to ECDSA_sign_ex(3), the parameter `type` is ignored. Additionally,
// `kinv` and `rp` are optional parameters that are used to precompute parts of
// the signing operation (we ignore those here since the engine is not
// performing any crypto calculations itself).
//
// Returns 1 on success; otherwise, returns 0.
int SignEx(int type, const unsigned char *digest_bytes, int digest_length,
           unsigned char *signature_return, unsigned int *signature_length,
           const BIGNUM */*kinv*/, const BIGNUM */*rp*/, EC_KEY *ec_key) {
  // Convert arguments to engine-native structures for convenience. These
  // conversions need to take place within the bridge layer (as opposed to
  // letting the `RsaKey::Sign` method handling the conversions) since the
  // conversion functions refer to some OpenSSL API functions.
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      const CryptoKeyHandle *crypto_key_handle,
      GetCryptoKeyHandleFromOpenSslEcKey(ec_key), 0);
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

  // Copy results into the return pointers.
  if (signature_length != nullptr) {
    *signature_length = signature.length();
  }
  if (signature_return != nullptr) {
    // Sanity check on `ECDSA_size` and the length of the signature.
    int ec_size = ECDSA_size(ec_key);
    if (ec_size < 0) {
      KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kFailedPrecondition,
                                    "ECDSA_size(ec_key) was < 0"));
      return 0;
    }
    if (signature.length() > static_cast<std::string::size_type>(ec_size)) {
      KMSENGINE_SIGNAL_ERROR(
          Status(StatusCode::kFailedPrecondition,
                 "Generated signature length was unexpectedly larger than "
                 "ECDSA_size(ec_key)"));
      return 0;
    }
    signature.copy(reinterpret_cast<char *>(signature_return),
                   signature.length());
  }
  return 1;
}

// Engine implementation for `ECDSA_sign_setup`.
//
// Used to precompute parts of the signing operation. `ec_key` is the private
// EC key and `context` is a pointer to `BN_CTX` structure (meaning "BIGNUM
// context"). `context` may be null. The precomputed values returned in `kinv`
// and `rp` are intended to be used in a later call to `ECDSA_sign_ex` or
// `ECDSA_do_sign_ex`.
//
// Since the engine is not actually performing any crypto operations, we don't
// really need this function. Our implementation ignores `ec_key` and `context`
// and sets `*kinv` and `*rp` to nullptr.
//
// Returns 1 on success; otherwise, returns 0.
int SignSetup(EC_KEY */*ec_key*/, BN_CTX */*context*/, BIGNUM **kinv,
              BIGNUM **rp) {
  // Set `*kinv` and `*rp` to nullptr, since calling code should not expect
  // `*kinv` and `*rp` to be populated after calling this function.
  if (kinv != nullptr) {
    *kinv = nullptr;
  }
  if (rp != nullptr) {
    *rp = nullptr;
  }

  return 1;
}

// Engine implementation for `ECDSA_do_sign_ex`.
//
// Computes a digital signature of the dgst_len bytes hash value dgst using the
// private key eckey and the optional pre-computed values kinv and rp. The
// signature is returned in a newly allocated ECDSA_SIG structure (or NULL on
// error).
//
// Returns a pointer to an allocated ECDSA_SIG structure or NULL on error.
ECDSA_SIG *DoSignEx(const unsigned char *digest_bytes, int digest_length,
                    const BIGNUM *kinv, const BIGNUM *rp,
                    EC_KEY *ec_key) {
  OpenSslEcdsaSignature ecdsa_signature = MakeEcdsaSignature();
  if (ecdsa_signature == nullptr) {
    KMSENGINE_SIGNAL_ERROR(
        Status(StatusCode::kResourceExhausted, "No memory available"));
    return nullptr;
  }

  // We reuse the engine's implementation for `ECDSA_sign_ex` to compute the
  // signature here.
  std::string signature('\0', ECDSA_size(ec_key));
  unsigned int signature_length;
  if (!ECDSA_sign_ex(0, digest_bytes, digest_length,
                     reinterpret_cast<unsigned char *>(&signature[0]),
                     &signature_length, kinv, rp, ec_key)) {
    KMSENGINE_SIGNAL_ERROR(
        Status(StatusCode::kInternal, "ECDSA_sign_ex failed"));
    return nullptr;
  }

  // TODO(https://github.com/googleinterns/cloud-kms-oss-tools/pull/115#discussion_r470916594):
  // `DoSignEx` should convert the DER-encoded signature `signature` returned by
  // `SignEx` to an `ECDSA_SIG` instance. See link for a potential way to do
  // this.
  return nullptr;
}

// Engine implementation for `EC_KEY_generate_key` to generate a new `EC_KEY`.
//
// Currently unimplemented; may be implemented in the future if key generation
// support for ECDSA keys is needed.
//
// Returns 1 on success and 0 on error.
int GenerateKey(EC_KEY *ec_key) {
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return 0;
}

// Engine implementation for `ECDH_compute_key`.
//
// Currently unimplemented, and should not be implemented. This operation is
// specifically for ECDH keys, which are currently not supported by the Cloud
// KMS API.
//
// Returns the length of the computed key in bytes or -1 on error.
int ComputeKey(unsigned char **/*out*/, size_t */*outlen*/, const EC_POINT *,
               const EC_KEY *) {
  KMSENGINE_SIGNAL_ERROR(
      Status(StatusCode::kUnimplemented, "Unsupported operation"));
  return -1;
}

}  // namespace

StatusOr<OpenSslEcKeyMethod> MakeKmsEcKeyMethod() {
  // `MakeEcKeyMethod` performs a shallow copy of the given `EC_KEY_METHOD`.
  // Here, we set it to `EC_KEY_OpenSsl()`, which returns the default OpenSSL
  // `EC_KEY_METHOD` implementation. This allows us to immediately "borrow"
  // default implementations for public key-related operations given that the
  // engine has direct access to public key material.
  OpenSslEcKeyMethod ec_key_method = MakeEcKeyMethod(EC_KEY_OpenSSL());
  if (ec_key_method == nullptr) {
    return Status(StatusCode::kResourceExhausted, "No memory available");
  }

  // Unlike their `RSA_meth_set*` counterparts, the `EC_KEY_METHOD_set_*`
  // functions have return type `void` and thus do not need to be error-checked.

  // Implementations for `ECDSA_verify` and `ECDSA_do_verify` are not explicitly
  // set here, since the engine will just reuse the default implementation for
  // `ECDSA_verify` and `ECDSA_do_verify` from `EC_KEY_OpenSSL()` (which
  // have already been copied into `ec_key_method`).

  // `EC_KEY_METHOD_set_init` sets multiple callback functions that are used
  // for `EC_KEY`-related memory management. (As stated in
  // EC_KEY_METHOD_set_init(3), all of the `EC_KEY_METHOD_set_init`
  // callbacks are null in the default OpenSSL implementation, so they are
  // optional callbacks.)
  //
  // See https://man.openbsd.org/EC_KEY_METHOD_new.3#EC_KEY_METHOD_set_init
  // for explanations of each callback and where the callbacks are called.
  //
  // The `init` callback is set to null since the key loader is responsible
  // for initializing `EC_KEY` structs to have meaningful engine-specific
  // data. Thus, we don't need to do any initialization work in the
  // `EC_KEY_METHOD` `init` callback.
  //
  // The callbacks for `set_group`, `set_private`, and `set_public` are
  // set to null since the engine does not need them for its implementation.
  EC_KEY_METHOD_set_init(ec_key_method.get(),
                         /*init=*/nullptr,
                         Finish, Copy,
                         /*set_group=*/nullptr,
                         /*set_private=*/nullptr,
                         /*set_public=*/nullptr);

  // `EC_KEY_METHOD_set_sign` consumes three functions: the first function
  // is the implementation for `ECDSA_sign_ex`, the second function is for
  // `ECDSA_sign_setup`, and the third function is for `ECDSA_do_sign_ex`.
  EC_KEY_METHOD_set_sign(ec_key_method.get(),
                         SignEx, SignSetup, DoSignEx);

  // `EC_KEY_METHOD_set_keygen` sets the function that implements
  // `EC_KEY_generate_key`.
  EC_KEY_METHOD_set_keygen(ec_key_method.get(), GenerateKey);

  // `EC_KEY_METHOD_set_compute_key` sets the function that implements
  // `ECDH_compute_key`.
  EC_KEY_METHOD_set_compute_key(ec_key_method.get(), ComputeKey);

  return ec_key_method;
}

}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine