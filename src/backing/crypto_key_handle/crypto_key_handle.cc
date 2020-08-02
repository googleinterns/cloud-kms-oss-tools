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

#include "src/backing/crypto_key_handle/crypto_key_handle.h"

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "src/backing/client/digest_case.h"
#include "src/backing/client/public_key.h"
#include "src/backing/status/status_or.h"

namespace kmsengine {
namespace backing {
namespace {

// Implementation of `CryptoKeyHandle`.
class KmsCryptoKeyHandle : public CryptoKeyHandle {
 public:
  KmsCryptoKeyHandle(std::string key_resource_id, Client const& client)
      : key_resource_id_(key_resource_id), client_(client) {}
  ~KmsCryptoKeyHandle() = default;

  // Methods from `CryptoKeyHandle`.
  std::string key_resource_id() const override {
    return key_resource_id_;
  }

  StatusOr<std::string> Sign(DigestCase digest_type, std::string digest_bytes)
      const override {
    return client_.AsymmetricSign(key_resource_id(), digest_type, digest_bytes);
  }

  StatusOr<PublicKey> GetPublicKey() const override {
    return client_.GetPublicKey(key_resource_id());
  }

 private:
  const std::string key_resource_id_;
  const Client const& client_;
};

}  // namespace

StatusOr<std::unique_ptr<CryptoKeyHandle>> MakeCryptoKeyHandle(
    std::string key_resource_id, Client const& client) {
  auto handle = absl::make_unique<KmsCryptoKeyHandle>(key_resource_id, client);
  if (handle == nullptr) {
    return Status(StatusCode::kResourceExhausted,
                  absl::StrFormat("Unable to allocate memory for "
                                  "CryptoKeyHandle '%s'", key_resource_id));
  }
  return handle;
}

}  // namespace backing
}  // namespace kmsengine
