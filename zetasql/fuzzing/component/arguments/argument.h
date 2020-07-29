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

#include <string>
#include <memory>
#include "zetasql/fuzzing/component/fuzz_targets/fuzz_target.h"

namespace zetasql_fuzzer {

class Argument {
 public:
  virtual void Accept(zetasql_fuzzer::FuzzTarget& function) = 0;
};

template <typename ArgType>
class TypedArg : public Argument {
 public:
  TypedArg(const ArgType& value) : argument(std::make_unique<ArgType>(value)) {}
  TypedArg(ArgType&& value) : argument(std::make_unique<ArgType>(value)) {}
  // Use referece or value?
  std::unique_ptr<ArgType> ReleaseArg() { return std::move(argument); }

 private:
  std::unique_ptr<ArgType> argument;
};

class SQLStringArg : public TypedArg<std::string> {
 public:
  using TypedArg::TypedArg;
  virtual void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }
};

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_ARGUMENT_H