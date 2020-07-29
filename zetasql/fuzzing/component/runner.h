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

#include <memory>
#include <functional>
#include "zetasql/fuzzing/component/fuzz_targets/fuzz_target.h"
#include "zetasql/fuzzing/component/arguments/argument.h"

namespace zetasql_fuzzer {

template<typename InputType, typename TargetType, typename ... Functions>
void Run(const InputType& input, Functions... functions) {
  TargetType target;
  std::function<std::unique_ptr<Argument>(const InputType&)>
      extractors[sizeof...(functions)] = {functions...};
  for (auto& extractor : extractors) {
    extractor(input)->Accept(target);
  }
  target.Execute();
}

// REMOVE IF NOT USED
// We explicitly specifiy input type because all visitors and 
// input should conform to the same type.
// template<typename InputType, typename TargetType>
// class Runner {
//  public:
//   using FunctionType = std::function<std::unique_ptr<Argument>(const InputType&)>;
//   Runner() {}
//   void Run(const InputType& input) {
//     for (const FunctionType& extractor : argument_extracters) {
//       extractor(input)->Accept(target);
//     }
//     target.Execute();
//   }

//  private:
//   const std::vector<FunctionType> argument_extracters;
//   TargetType target;
// };

}  // namespace zetasql_fuzzer

#endif  //ZETASQL_FUZZING_RUNNER_H