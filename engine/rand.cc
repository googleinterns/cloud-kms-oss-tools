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

#include "engine/rand.h"

#include <cstring>

#include "google/cloud/kms/v1/resources.grpc.pb.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "grpc/grpc.h"

namespace engine {

int RandMethod::bytes(unsigned char *buffer, int num) {
  std::memset(buffer, 60, num);
  return num;
}

int RandMethod::status() {
  // Very tiny (and meaningless) example of how to refer to Cloud KMS gRPC
  // constructs in C++. GOOGLE_SYMMETRIC_ENCRYPTION is just an enum that equals
  // 1.
  auto example = google::cloud::kms::v1::CryptoKeyVersion::GOOGLE_SYMMETRIC_ENCRYPTION;
  return example;
}

}  // namespace engine
