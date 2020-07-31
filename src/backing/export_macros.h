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

#ifndef KMSENGINE_BACKING_EXPORT_MACROS_H_
#define KMSENGINE_BACKING_EXPORT_MACROS_H_

// To avoid symbol conflicts between the backing layer and the bridge layer,
// this file defines two macros used to declare which symbols defined in the
// backing layer are "visible" to the bridge layer:
//
//    - KMSENGINE_EXPORT, which declares that a particular symbol should be made
//      visible to the bridge layer.
//
//    - KMSENGINE_LOCAL, which declares that a particular symbol is only
//      internally used and should not be made visible to the bridge layer.
//
// These macros are intended to be used in conjunction with the
// "-fvisibility=hidden" compiler flag, which tells the C++ compiler that every
// declaration not explicitly marked with a visibility attribute has a "hidden"
// visibility (equivalent to marking the symbol with the KMSENGINE_LOCAL macro).
// The Bazel rule for building the backing layer shared object builds the shared
// object with the "-fvisibility=hidden" flag enabled across the entire build.
//
// Classes and enums that need to be referenced in the bridge layer should be
// marked with KMSENGINE_EXPORT.
//
//    Example:
//
//        class KMSENGINE_EXPORT MyClass { ... };
//
//        enum KMSENGINE_EXPORT MyEnum { ... };
//
// Functions that need to be marked with KMSENGINE_EXPORT are those that satisfy
// the following conditions:
//
//    1) The function is expected to be called from the bridge layer.
//
//    2) The function's implementation is declared in a source file (not a
//       header file). Any functions declared in a header file that is #included
//       by the bridge layer will be visible to the bridge layer as the
//       implementation of the function is directly in the header file.
//       Pure virtual functions or functions declared to have "default"
//       implementation do not need to be marked with KMSENGINE_EXPORT.
//
//    Example:
//
//        KMSENGINE_EXPORT int MyFunction(...) { ... }
//
// In general, marking functions with KMSENGINE_LOCAL is not necessary due to
// the global usage of the "-fvisibility=hidden" flag described above. However,
// there is one case in which explicitly marking a function with KMSENGINE_LOCAL
// is useful: individual member functions of an exported class that are not
// part of the interface (in particular, ones which are private), and are not
// used by friend code, should be marked individually with KMSENGINE_LOCAL. This
// allows the compiler to generate more optimal code and results in a smaller
// library size.
//
//    Example:
//
//        class KMSENGINE_EXPORT MyExportedClass {
//         public:
//          ...
//
//         private:
//          KMSENGINE_LOCAL int MyPrivateFunction(...) { ... }
//
//          // Member variables should not be marked with KMSENGINE_LOCAL; the
//          // compiler will ignore visibility declarations on member variables.
//          std::string my_member_variable_;
//        }
//

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define KMSENGINE_EXPORT __attribute__ ((dllexport))
    #else
      #define KMSENGINE_EXPORT __declspec(dllexport)
    #endif
  #else
    #ifdef __GNUC__
      #define KMSENGINE_EXPORT __attribute__ ((dllimport))
    #else
      #define KMSENGINE_EXPORT __declspec(dllimport)
    #endif
  #endif
  #define KMSENGINE_LOCAL
#else
  #if __GNUC__ >= 4
    #define KMSENGINE_EXPORT __attribute__ ((visibility ("default")))
    #define KMSENGINE_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define KMSENGINE_EXPORT
    #define KMSENGINE_LOCAL
  #endif
#endif

#endif  // KMSENGINE_BACKING_EXPORT_MACROS_H_
