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

#ifndef ZETASQL_FUZZING_RUNNER_H
#define ZETASQL_FUZZING_RUNNER_H

#include <functional>
#include <memory>

#include "zetasql/fuzzing/component/fuzz_targets/fuzz_target.h"

namespace zetasql_fuzzer {

template <typename InputType, typename TargetType, typename... Functions>
void Run(const InputType& input, Functions... functions) {
  TargetType target;
  for (const std::function<void(const InputType&, FuzzTarget&)>&
           extract_and_apply : {functions...}) {
    extract_and_apply(input, target);
  }
  target.Execute();
}

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_RUNNER_H