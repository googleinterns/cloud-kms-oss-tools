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

#include <cstring>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>

#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/memory_util/openssl_structs.h"
#include "src/bridge/memory_util/openssl_bio.h"
#include "src/bridge/crypto/ec.h"
#include "src/testing_util/mock_crypto_key_handle.h"
#include "src/testing_util/openssl_assertions.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace crypto {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::testing::NotNull;

// A random 2048-bit / 256-byte ECDSA public key, encoded in PEM format.
constexpr char kEcdsaPublicKey[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xOUetsCa8EfOlDEBAfREhJqspDo\n"
  "yEh6Szz2in47Tv5n52m9dLYyPCbqZkOB5nTSqtscpkQD/HpykCggvx09iQ==\n"
  "-----END PUBLIC KEY-----\n";

// Creates an `OpenSslEcKey` from the PEM-encoded public key data loaded in
// `public_key_bio`. Returns an error `Status` if unsuccessful.
//
// The `EC_KEY` struct contained within the returned `OpenSslEcKey` will have
// its public key parameters set to the values from the input PEM.
StatusOr<OpenSslEcKey> MakeEcKeyFromPublicKeyPemBio(OpenSslBio public_key_bio) {
  RSA *rsa = PEM_read_bio_EC_PUBKEY(public_key_bio.get(), nullptr,
                                     nullptr, nullptr);
  if (rsa == nullptr) {
    return Status(StatusCode::kInternal, "PEM_read_bio_EC_PUBKEY failed");
  }
  return OpenSslEcKey(rsa, &RSA_free);
}

// Test fixture for calling initialization functions (normally called by the
// `EngineBind` function) needed for the RSA callbacks to work.
class EcKeyMethodTest : public ::testing::Test {
 protected:
  EcKeyMethodTest() : ec_key_method_(nullptr, nullptr) {}

  void SetUp() override {
    StatusOr<OpenSslEcKeyMethod> kms_ec_key_method_or = MakeKmsEcKeyMethod();
    ASSERT_THAT(kms_ec_key_method_or, IsOk());
    ec_key_method_ = std::move(kms_ec_key_method_or.value());

    ASSERT_THAT(InitExternalIndices(), IsOk());
    ASSERT_THAT(ec_key_method(), NotNull());
  }

  void TearDown() override {
    FreeExternalIndices();
  }

  // Convenience function for making an RSA struct with the Cloud KMS
  // EC_KEY_METHOD implementation already attached.
  StatusOr<OpenSslEcKey> MakeRsaWithKmsMethod() {
    KMSENGINE_ASSIGN_OR_RETURN(
        OpenSslBio pem_bio,
        MakeOpenSslMemoryBufferBio(kEcdsaPublicKey, sizeof(kEcdsaPublicKey)));
    KMSENGINE_ASSIGN_OR_RETURN(
        OpenSslEcKey ec_key, MakeEcKeyFromPublicKeyPemBio(std::move(pem_bio)));
    EC_KEY_set_method(ec_key.get(), ec_key_method());
    return ec_key;
  }

  EC_KEY_METHOD *ec_key_method() { return ec_key_method_.get(); }

 private:
  OpenSslEcKeyMethod ec_key_method_;
};

TEST_F(EcKeyMethodTest, EcKeyMethodInitCallbacksAreInitialized) {
  // Our implementation sets the `finish` and `copy` callbacks, so we check that
  // they're defined here.
  int (*finish)(EC_KEY *);
  int (*copy)(EC_KEY *, const EC_KEY *);
  EC_KEY_METHOD_get_init(/*init=*/nullptr, &finish, &copy,
                         /*set_group=*/nullptr, /*set_private=*/nullptr,
                         /*set_public=*/nullptr);

  EXPECT_THAT(finish, NotNull());
  EXPECT_THAT(copy, NotNull());
}

TEST_F(EcKeyMethodTest, EcKeyMethodSignCallbacksAreInitialized) {
  int (*sign)(int, const unsigned char *, int, unsigned char *, unsigned int *,
              const BIGNUM *, const BIGNUM *, EC_KEY *);
  int (*sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);
  ECDSA_SIG *(*sign_sig)(const unsigned char *, int, const BIGNUM *,
                         const BIGNUM *, EC_KEY *);
  EC_KEY_METHOD_get_sign(&sign, &sign_setup, &sign_sig);

  EXPECT_THAT(sign, NotNull());
  EXPECT_THAT(sign_setup, NotNull());
  EXPECT_THAT(sign_sig, NotNull());
}

TEST_F(EcKeyMethodTest, EcKeyMethodVerifyCallbacksAreInitialized) {
  int (*verify)(int, const unsigned char *, int, const unsigned char *, int,
                EC_KEY *);
  int (*verify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);
  EC_KEY_METHOD_get_verify(&verify, &verify_sig);

  EXPECT_THAT(verify, NotNull());
  EXPECT_THAT(verify_sig, NotNull());
}

TEST_F(EcKeyMethodTest, EcKeyMethodKeygenCallbacksAreInitialized) {
  int (*pkeygen)(EC_KEY *)
  EC_KEY_METHOD_get_keygen(&pkeygen);

  EXPECT_THAT(pkeygen, NotNull());
}

TEST_F(EcKeyMethodTest, EcKeyMethodKeygenCallbacksAreInitialized) {
  int (*compute_key)(void *, size_t, const EC_POINT *, EC_KEY *,
                     void *(*KDF) (const void *, size_t , void *, size_t *));
  EC_KEY_METHOD_get_compute_key(&compute_key);

  EXPECT_THAT(compute_key, NotNull());
}

}  // namespace
}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine
