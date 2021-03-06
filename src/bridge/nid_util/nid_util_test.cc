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

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "src/backing/client/digest_case.h"
#include "src/bridge/nid_util/nid_util.h"
#include "src/testing_util/test_matchers.h"

namespace kmsengine {
namespace bridge {
namespace {

using ::kmsengine::backing::DigestCase;
using ::kmsengine::testing_util::IsOk;
using ::testing::Not;
using ::testing::Values;
using ::testing::ValuesIn;

// Mapping from OpenSSL NIDs associated with `EVP_PKEY` objects to their
// engine-native equivalent.
struct CorrespondingNid {
  int actual;
  DigestCase expected;
};

const CorrespondingNid kNidMapping[] = {
  {EVP_MD_type(EVP_sha256()), DigestCase::kSha256},
  {EVP_MD_type(EVP_sha384()), DigestCase::kSha384},
  {EVP_MD_type(EVP_sha512()), DigestCase::kSha512},
};

class ValidNidTest : public testing::TestWithParam<CorrespondingNid> {
  // Purposely empty; no fixtures to instantiate.
};

INSTANTIATE_TEST_SUITE_P(ValidNids, ValidNidTest, ValuesIn(kNidMapping));

TEST_P(ValidNidTest, ConvertOpenSslNidToDigestType) {
  auto mapping = GetParam();
  auto actual = ConvertOpenSslNidToDigestType(mapping.actual);
  EXPECT_THAT(actual, IsOk());
  EXPECT_EQ(actual.value(), mapping.expected);
}

class InvalidNidTest : public testing::TestWithParam<int> {
  // Purposely empty; no fixtures to instantiate.
};

// There are thousands of unique NIDs for different types of objects, but
// the underlying NIDs of the EVP message digest types are the only ones that
// will should realistically touch `ConvertOpenSslNidToDigestType`, so we test
// those explicitly.
//
// See https://cloud.google.com/kms/docs/algorithms for a list of valid
// digests and associated algorithms for the Cloud KMS service.
INSTANTIATE_TEST_SUITE_P(InvalidNids, InvalidNidTest,
                         Values(EVP_MD_type(EVP_md5()),
                                EVP_MD_type(EVP_sha1()),
                                EVP_MD_type(EVP_sha224()),
                                EVP_MD_type(EVP_ripemd160())));

TEST_P(InvalidNidTest, ReturnsErrorStatusForInvalidNIDs) {
  EXPECT_THAT(ConvertOpenSslNidToDigestType(GetParam()), Not(IsOk()));
}

}  // namespace
}  // namespace bridge
}  // namespace kmsengine
