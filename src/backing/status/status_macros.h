/**
 * Original copyright 2015 The TensorFlow Authors. All Rights Reserved.
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
 *
 * Modifications copyright 2020 Google LLC:
 *
 *    - Renamed macros
 *    - Added example usage
 *
 * Modifications licensed under the Apache License, Version 2.0 (the "License");
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

// Definitions for KMSENGINE_RETURN_IF_ERROR and KMSENGINE_ASSIGN_OR_RETURN,
// helper macros for dealing with the StatusOr<T> datatype.
//
// Example usage:
//
//    StatusOr<int> ReadNumber(const std::string& path) {
//      std::string data;
//      KMSENGINE_RETURN_IF_ERROR(GetContents(path, &data));
//
//      KMSENGINE_ASSIGN_OR_RETURN(int number, ParseInt(data));
//      return number;
//    }
//
// This is equivalent to:
//
//    StatusOr<int> ReadNumber(const std::string& path) {
//      std::string data;
//      auto status = GetContents(path, &data);
//      if (!status.ok()) return status;
//
//      auto number_or = ParseInt(data;)
//      if (!number_or.ok()) {
//        return number_or.status()
//      }
//
//      return number.ConsumeValueOrDie();
//    }
//

#ifndef KMSENGINE_KMS_INTERFACE_STATUS_MACROS_H_
#define KMSENGINE_KMS_INTERFACE_STATUS_MACROS_H_

// Early-returns the status if it is in error; otherwise, proceeds.
//
// The argument expression is guaranteed to be evaluated exactly once.
#define KMSENGINE_RETURN_IF_ERROR(__status) \
  do {                                      \
    auto status = __status;                 \
    if (!status.ok()) {                     \
      return status;                        \
    }                                       \
  } while (false)

// Helper macros to create identifiers from concatenation.
#define __KMSENGINE_MACRO_CONCAT_INNER(__x, __y) __x##__y
#define __KMSENGINE_MACRO_CONCAT(__x, __y) \
  __KMSENGINE_MACRO_CONCAT_INNER(__x, __y)

// Implementation of KMSENGINE_ASSIGN_OR_RETURN that uses a unique temporary
// identifier for avoiding collision in the enclosing scope.
#define __KMSENGINE_ASSIGN_OR_RETURN_IMPL(__lhs, __rhs, __name) \
  auto __name = (__rhs);                                        \
  if (!__name.ok()) {                                           \
    return __name.status();                                     \
  }                                                             \
  __lhs = std::move(__name.value());

// Early-returns the status if it is in error; otherwise, assigns the
// right-hand-side expression to the left-hand-side expression.
//
// The right-hand-side expression is guaranteed to be evaluated exactly once.
#define KMSENGINE_ASSIGN_OR_RETURN(__lhs, __rhs) \
  __KMSENGINE_ASSIGN_OR_RETURN_IMPL(             \
    __lhs, __rhs,                                \
    __KMSENGINE_MACRO_CONCAT(__status_or_value,  \
                             __COUNTER__))

#endif  // KMSENGINE_KMS_INTERFACE_STATUS_MACROS_H_
