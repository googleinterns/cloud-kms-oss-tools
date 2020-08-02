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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "absl/memory/memory.h"
#include "src/bridge/memory_util/openssl_bio.h"
#include "src/bridge/key_loader/rsa_key_loader.h"
#include "src/testing_util/mock_crypto_key_handle.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace key_loader {
namespace {

using ::kmsengine::testing_util::IsOk;
using ::kmsengine::testing_util::MockCryptoKeyHandle;

// A random 2048-bit / 256-byte RSA public key, encoded in PEM format.
constexpr char kRsaPublicKey[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
  "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"
  "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"
  "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"
  "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"
  "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"
  "wQIDAQAB\n"
  "-----END PUBLIC KEY-----\n";

TEST(RsaKeyLoaderTest, MakeKmsRsaEvpPkey) {
  auto public_key_pem_bio = MakeOpenSslBioFromString(kRsaPublicKey);
  auto crypto_key_handle = absl::make_unique<MockCryptoKeyHandle>();
  auto rsa_method = rsa::MakeKmsRsaMethod();

  auto evp_pkey_status_or = MakeKmsRsaEvpPkey(std::move(public_key_pem_bio),
                                              std::move(crypto_key_handle),
                                              rsa_method.get());
  ASSERT_THAT(evp_pkey_status_or, IsOk());
  auto evp_pkey = evp_pkey_status_or.value();

  EXPECT_EQ(EVP_PKEY_type(evp_pkey.get()), EVP_PKEY_RSA);
}

}  // namespace
}  // namespace key_loader
}  // namespace bridge
}  // namespace kmsengine
