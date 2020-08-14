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

#include <utility>

#include "src/backing/client/crypto_key_version_algorithm.h"
#include "src/backing/crypto_key_handle/crypto_key_handle.h"
#include "src/backing/status/status.h"
#include "src/backing/status/status_or.h"
#include "src/bridge/error/error.h"
#include "src/bridge/ex_data_util/ex_data_util.h"
#include "src/bridge/key_loader/rsa_key_loader.h"
#include "src/bridge/memory_util/openssl_bio.h"
#include "src/bridge/memory_util/openssl_structs.h"

namespace kmsengine {
namespace bridge {

using ::kmsengine::backing::CryptoKeyHandle;
using ::kmsengine::backing::PublicKey;

EVP_PKEY *LoadCloudKmsKey(ENGINE *engine, const char *key_id,
                          UI_METHOD */*ui_method*/, void */*callback_data*/) {
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      EngineData *engine_data, GetEngineDataFromOpenSslEngine(engine), nullptr);
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      std::unique_ptr<CryptoKeyHandle> crypto_key_handle,
      backing::MakeCryptoKeyHandle(key_id, engine_data->client()), nullptr);
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      PublicKey public_key, crypto_key_handle->GetPublicKey(), nullptr);

  // OpenSSL provides parsing functions to generate `RSA` and `EC_KEY` structs
  // from PEM-encoded key material. These parsing functions consume the data
  // as an OpenSSL `BIO` stream, so we need to load the PublicKey's pem into a
  // `BIO` before attempting to parse the public key material.
  KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
      OpenSslBio public_key_pem_bio, MakeOpenSslMemoryBufferBio(
          static_cast<const void *>(public_key.pem().data()),
          public_key.pem().length()),
      nullptr);

  OpenSslEvpPkey evp_pkey {nullptr, nullptr};
  using ::kmsengine::backing::CryptoKeyVersionAlgorithm;
  switch (public_key.algorithm()) {
    case CryptoKeyVersionAlgorithm::kRsaSignPss2048Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPss3072Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPss4096Sha512:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs2048Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs3072Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha256:
    case CryptoKeyVersionAlgorithm::kRsaSignPkcs4096Sha512:
      {
        KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
            evp_pkey,
            key_loader::MakeKmsRsaEvpPkey(std::move(public_key_pem_bio),
                                          std::move(crypto_key_handle),
                                          engine_data->rsa_method()),
            nullptr);
        break;
      }
    case CryptoKeyVersionAlgorithm::kEcSignP256Sha256:
    case CryptoKeyVersionAlgorithm::kEcSignP384Sha384:
      {
        // TODO: uncomment when #113 is merged in.
        // KMSENGINE_ASSIGN_OR_RETURN_WITH_OPENSSL_ERROR(
        //     evp_pkey,
        //     key_loader::MakeKmsEcEvpPkey(std::move(public_key_pem_bio),
        //                                  std::move(crypto_key_handle),
        //                                  engine_data->ec_key_method()),
        //     nullptr);
        // break;
        KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kFailedPrecondition,
            "Cloud KMS key had unsupported type " +
            CryptoKeyVersionAlgorithmToString(public_key.algorithm())));
        break;
      }
    default:
      {
        KMSENGINE_SIGNAL_ERROR(Status(StatusCode::kFailedPrecondition,
            "Cloud KMS key had unsupported type " +
            CryptoKeyVersionAlgorithmToString(public_key.algorithm())));
        break;
      }
  }

  // Calling code assumes ownership (and cleanup responsibility) for the
  // `EVP_PKEY` at this point.
  return evp_pkey.release();
}

}  // namespace bridge
}  // namespace kmsengine
