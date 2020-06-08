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

// We don't need to wrap this in extern "C" since it's already done so in OpenSSL
#include <openssl/engine.h>

#include "rand.h"

namespace engine {
    static const char *hsm_engine_id = "gcloudhsm";
    static const char *hsm_engine_name = "Test engine for Cloud HSM";

    // Implements OpenSSL's RAND_METHOD declaration.
    static const RAND_METHOD hsm_rand_method = {
        NULL,                   // seed
        RandMethod::bytes,      // bytes
        NULL,                   // cleanup
        NULL,                   // add
        NULL,                   // pseudorand
        RandMethod::status      // status
    };

    static int hsm_engine_init(ENGINE *e)
    {
        printf("Engine init\n");
        return 1;
    }

    static int bind_helper(ENGINE *e, const char *id) {
        // TODO: might need to do ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL),
        // but not sure why (see eng_rdrand.c from openssl codebase)
        if (!ENGINE_set_id(e, engine::hsm_engine_id) ||
            !ENGINE_set_name(e, engine::hsm_engine_name) ||
            !ENGINE_set_init_function(e, engine::hsm_engine_init) ||
            !ENGINE_set_RAND(e, &engine::hsm_rand_method)) {
            return 0;
        }
        return 1;
    }
}

extern "C" {
    IMPLEMENT_DYNAMIC_CHECK_FN();
    IMPLEMENT_DYNAMIC_BIND_FN(engine::bind_helper);
}
