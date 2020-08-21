//
// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef ZETASQL_FUZZING_FUZZER_MACRO_H
#define ZETASQL_FUZZING_FUZZER_MACRO_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "libprotobuf_mutator/src/libfuzzer/libfuzzer_macro.h"
#include "zetasql/fuzzing/component/runner.h"

// Defines a fuzzer with input of InputType, extracted by 
// __VA_ARGS__ of argument extractors, and applied to the fuzz target of TargetType.
#define ZETASQL_PROTO_FUZZER(InputType, TargetType, ...)            \
  DEFINE_PROTO_FUZZER(const InputType& input) {                     \
    zetasql_fuzzer::Run<InputType, TargetType>(input, __VA_ARGS__); \
  }

// Defines a fuzzer with input interpreted as a string, extracted by 
// __VA_ARGS__ of argument extractors, and applied to the fuzz target of TargetType.
#define ZETASQL_SIMPLE_FUZZER(TargetType, ...)                              \
  extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) { \
    const std::string input(reinterpret_cast<const char*>(Data), Size);     \
    zetasql_fuzzer::Run<std::string, TargetType>(input, __VA_ARGS__);       \
    return 0;                                                               \
  }

#endif  // ZETASQL_FUZZING_FUZZER_MACRO_H