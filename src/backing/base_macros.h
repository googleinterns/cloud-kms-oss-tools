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

#ifndef KMSENGINE_BACKING_BASE_H_
#define KMSENGINE_BACKING_BASE_H_

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define BRIDGE_EXPORT __attribute__ ((dllexport))
    #else
      #define BRIDGE_EXPORT __declspec(dllexport)
    #endif
  #else
    #ifdef __GNUC__
      #define BRIDGE_EXPORT __attribute__ ((dllimport))
    #else
      #define BRIDGE_EXPORT __declspec(dllimport)
    #endif
  #endif
  #define BRIDGE_LOCAL
#else
  #if __GNUC__ >= 4
    #define BRIDGE_EXPORT __attribute__ ((visibility ("default")))
    #define BRIDGE_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define BRIDGE_EXPORT
    #define BRIDGE_LOCAL
  #endif
#endif

#endif  // KMSENGINE_BACKING_BASE_H_
