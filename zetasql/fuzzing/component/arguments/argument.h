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
#include <string>

#include "zetasql/base/statusor.h"
#include "zetasql/fuzzing/component/fuzz_targets/fuzz_target.h"

// Argument defines an abstraction for any value that is extracted from 
// the fuzzing input of InputType in zetasql_fuzzer::Run function,
// and is to be applied to some zetasql_fuzzer::FuzzTarget in a fuzzing test.
//
// Argument is a Visitable to zetasql_fuzzer::FuzzTarget

namespace zetasql_fuzzer {

// Defines a type-erased abstract base class
class Argument {
 public:
  virtual ~Argument() = default;

  // Accepts a FuzzTarget as a Visitor to this Argument
  virtual void Accept(zetasql_fuzzer::FuzzTarget& function) = 0;
};

// Defines a move-only template argument container holding value of ArgType
template <typename ArgType>
class TypedArg : public Argument {
 public:
  TypedArg() = delete;
  TypedArg(const TypedArg<ArgType>&) = delete;
  TypedArg& operator=(const TypedArg<ArgType>&) = delete;

  TypedArg(TypedArg<ArgType>&&) = default;
  TypedArg& operator=(TypedArg<ArgType>&&) = default;

  TypedArg(const ArgType& value) : argument_(std::make_unique<ArgType>(value)) {}
  TypedArg(ArgType&& value) : argument_(std::make_unique<ArgType>(value)) {}
  TypedArg(std::unique_ptr<ArgType> pointer) : argument_(std::move(pointer)) {}

  virtual ~TypedArg() = default;

  zetasql_base::StatusOr<std::unique_ptr<ArgType>> Release() {
    if (argument_) {
      return std::move(argument_);
    }
    return absl::NotFoundError(
        "Argument is either not set or has been released.");
  }

 private:
  std::unique_ptr<ArgType> argument_;
};

// Defines an argument container for extracted SQL statement string 
// from input of InputType in zetasql_fuzzer::Run
class SQLStringArg : public TypedArg<std::string> {
 public:
  using TypedArg::TypedArg;
  void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }
};
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_ARGUMENT_H