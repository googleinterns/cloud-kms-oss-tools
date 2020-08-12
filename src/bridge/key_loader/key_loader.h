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

#ifndef KMSENGINE_BRIDGE_KEY_LOADER_KEY_LOADER_H_
#define KMSENGINE_BRIDGE_KEY_LOADER_KEY_LOADER_H_

#include <openssl/engine.h>

namespace kmsengine {
namespace bridge {

// Loads a Cloud HSM private key from the `key_id` file.
//
// Implements the `ENGINE_LOAD_KEY_PTR` prototype from OpenSSL for use with
// the `ENGINE_set_load_privkey_function` API function. OpenSSL will call
// this function directly and pass it the `key_id` specified by the end
// application.
//
// The `ui_method` and `callback_data` parameters are ignored.
//
// TODO(https://github.com/googleinterns/cloud-kms-oss-tools/issues/118): This
// is currently just treating the `key_id` path as the Cloud KMS key resource ID
// itself. However, Apache seems to require that the `key_id` exists as a real
// file, so we'll need to make this function read the key resource ID from
// a real file instead.
EVP_PKEY *LoadPrivateKey(ENGINE *engine, const char *key_id,
                         UI_METHOD *ui_method, void *callback_data);

}  // namespace bridge
}  // namespace kmsengine

#endif  // KMSENGINE_BRIDGE_KEY_LOADER_KEY_LOADER_H_
