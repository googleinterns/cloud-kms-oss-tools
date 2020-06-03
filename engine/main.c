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

#include <openssl/engine.h>

#include "wrapper.h"

static const char *hsm_engine_id = "hsm";
static const char *hsm_engine_name = "Test engine for Cloud HSM";

// Implements OpenSSL's RAND_METHOD declaration.
static RAND_METHOD hsm_rand_method = {
    NULL,                   // seed
    rand_method_bytes,      // bytes
    NULL,                   // cleanup
    NULL,                   // add
    NULL,                   // pseudorand
    rand_method_status      // status
};

static int hsm_engine_init(ENGINE *e)
{
    // Probably want to read from environment variable to get Cloud HSM config here
    printf("Engine init\n");
    return 1;
}

static int bind_helper(ENGINE *e, const char *id)
{
    // TODO: might need to do ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL),
    // but not sure why (see eng_rdrand.c from openssl codebase)
    if (!ENGINE_set_id(e, hsm_engine_id) ||
        !ENGINE_set_name(e, hsm_engine_name) ||
        !ENGINE_set_init_function(e, hsm_engine_init) ||
        !ENGINE_set_RAND(e, &hsm_rand_method)) {
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);
