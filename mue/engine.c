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

static const char *engine_id = "mue";
static const char *engine_name = "A minimum engine";

static int bind(ENGINE *e, const char *id)
{
    if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        return 0;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind);
IMPLEMENT_DYNAMIC_CHECK_FN();
