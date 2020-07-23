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

#ifndef ZETASQL_FUZZING_INPUT_VISITOR_H
#define ZETASQL_FUZZING_INPUT_VISITOR_H

#include <memory>
#include "zetasql/fuzzing/component/input.h"
#include "zetasql/fuzzing/component/argument.h"

namespace zetasql_fuzzer {

template<typename InputType>
class InputVisitor {
 public:
  virtual void Visit(const zetasql_fuzzer::Input<InputType>& input) = 0;
  virtual Argument Collect() = 0;
  virtual void Clear() = 0;
};

}  // namespace zetasql_fuzzer

#endif  //ZETASQL_FUZZING_INPUT_VISITOR_H