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

#ifndef ZETASQL_FUZZING_ARGUMENT_H
#define ZETASQL_FUZZING_ARGUMENT_H

#include <memory>

#include "zetasql/fuzzing/component/function.h"

namespace zetasql_fuzzer {

class Argument {
 public:
  virtual void Accept(zetasql_fuzzer::Function& function) const = 0;
};

template <typename T>
class PositionalArg : public Argument {
 public:
  PositionalArg(std::shared_ptr<const T> value) : argument(value) {}
  virtual void Accept(zetasql_fuzzer::Function& function) const override {
    function.Visit(*this);
  }
  const std::shared_ptr<const T> GetArgument() const { return argument; }
  const uint8_t GetPosition() const { return position; }

 private:
  std::shared_ptr<const T> argument;
  uint8_t position;
};

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_ARGUMENT_H