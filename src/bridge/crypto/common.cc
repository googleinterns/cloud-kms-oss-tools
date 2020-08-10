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

#include "src/bridge/crypto/common.h"

#include <string>

#include "src/backing/client/digest_case.h"
#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/nid_util/nid_util.h"

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

}  // namespace

Status CommonSign(int type, const unsigned char *digest_bytes,
                  int digest_length, unsigned char *signature_return,
                  unsigned int *signature_length,
                  const CryptoKeyHandle *crypto_key_handle) {
  // Convert arguments to engine-native structures for convenience. These
  // conversions need to take place within the bridge layer (as opposed to
  // letting the `RsaKey::Sign` method handling the conversions) since the
  // conversion functions refer to some OpenSSL API functions.
  KMSENGINE_ASSIGN_OR_RETURN(
      const DigestCase digest_type,
      ConvertOpenSslNidToDigestType(type));
  KMSENGINE_ASSIGN_OR_RETURN(
      const std::string digest_string,
      MakeDigestString(digest_bytes, digest_length));

  // Delegate handling of the signing operation to the backing layer.
  KMSENGINE_ASSIGN_OR_RETURN(
      const std::string signature,
      crypto_key_handle->Sign(digest_type, digest_string));

  // Copy results into the return pointers.
  if (signature_return != nullptr) {
    signature.copy(reinterpret_cast<char *>(signature_return),
                   signature.length());
  }
  if (signature_length != nullptr) {
    *signature_length = signature.length();
  }

  return Status::kOk;
}

}  // namespace crypto
}  // namespace bridge
}  // namespace kmsengine
