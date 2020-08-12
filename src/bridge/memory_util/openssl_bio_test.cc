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
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "src/bridge/memory_util/openssl_bio.h"
#include "src/testing_util/test_matchers.h"
#include "src/testing_util/openssl_assertions.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::testing::StrEq;
using ::kmsengine::testing_util::IsOk;

TEST(OpenSslBioTest, MakeOpenSslMemoryBufferBioContainsExpectedBytes) {
  constexpr char kSampleBuffer[] = "hello world!";

  StatusOr<OpenSslBio> public_key_bio_or = MakeOpenSslMemoryBufferBio(
      kSampleBuffer, sizeof(kSampleBuffer));
  ASSERT_THAT(public_key_bio_or, IsOk());
  auto public_key_bio = std::move(public_key_bio_or.value());

  char read_buffer[sizeof(kSampleBuffer)];
  EXPECT_OPENSSL_SUCCESS(BIO_read(public_key_bio.get(), read_buffer,
                                  /*num_bytes_to_read=*/sizeof(kSampleBuffer)));
  EXPECT_THAT(read_buffer, StrEq(kSampleBuffer));
}

TEST(OpenSslBioTest, MakeOpenSslMemoryBufferBioSetsDeleter) {
  constexpr char kSampleBuffer[] = "hello world!";

  StatusOr<OpenSslBio> public_key_bio_or = MakeOpenSslMemoryBufferBio(
      kSampleBuffer, sizeof(kSampleBuffer));
  ASSERT_THAT(public_key_bio_or, IsOk());
  auto public_key_bio = std::move(public_key_bio_or.value());

  EXPECT_EQ(public_key_bio.get_deleter(), &BIO_free);
}

TEST(OpenSslBioTest, MakeOpenSslMemoryBufferBioWorksWithRsaPemRead) {
  // Just a random 2048-bit RSA public key.
  constexpr char kRsaPublicKey[] = "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
    "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"
    "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"
    "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"
    "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"
    "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"
    "wQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

  StatusOr<OpenSslBio> public_key_bio_or = MakeOpenSslMemoryBufferBio(
      kRsaPublicKey, sizeof(kRsaPublicKey));
  ASSERT_THAT(public_key_bio_or, IsOk());
  auto public_key_bio = std::move(public_key_bio_or.value());

  // If `PEM_read_bio_RSA_PUBKEY` fails, make sure that the data in the pointer
  // given to `BIO_new_mem_buf` still exists after `MakeOpenSslMemoryBufferBio`
  // returns.
  EXPECT_OPENSSL_SUCCESS(
      PEM_read_bio_RSA_PUBKEY(public_key_bio.get(), nullptr, nullptr, nullptr));
}

TEST(OpenSslBioTest, MakeOpenSslMemoryBufferBioSetsDeleter) {
  auto public_key_bio_or = MakeOpenSslMemoryBufferBio(kRsaPublicKey,
                                                      sizeof(kRsaPublicKey));
  ASSERT_THAT(public_key_bio_or, IsOk());
  auto public_key_bio = std::move(public_key_bio_or.value());

  EXPECT_EQ(public_key_bio.get_deleter(), &BIO_free);
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
