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
#include "wrapper.h"

#include "rand.h"

// This file wraps around C++ functions that need to be exposed in the C library.
// Any C++ endpoint that should be exposed to the OpenSSL engine needs to have a
// wrapper function defined within `extern "C"`.
//
// extern "C" exposes all functions defined in this in this file to the C linker.
// See https://www.teddy.ch/c++_library_in_c/ for details.
extern "C"
{
    int rand_method_bytes(unsigned char *buf, int num) {
        return engine::RandMethod::bytes(buf, num);
    }

    int rand_method_status(void) {
        return engine::RandMethod::status();
    }
}  // extern "C"
