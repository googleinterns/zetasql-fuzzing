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
#include "zetasql/public/evaluator_base.h"

namespace zetasql_fuzzer {

class Argument {
 public:
  // Accepts a FuzzTarget as a Visitor to this Argument
  virtual void Accept(zetasql_fuzzer::FuzzTarget& function) = 0;
};

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

class SQLStringArg : public TypedArg<std::string> {
 public:
  using TypedArg::TypedArg;
  void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }
};

class ParameterValueMapArg : public TypedArg<zetasql::ParameterValueMap> {
 public:
  enum As { COLUMNS, PARAMETERS };

  ParameterValueMapArg() = delete;
  ParameterValueMapArg(const ParameterValueMapArg&) = delete;
  ParameterValueMapArg& operator=(const ParameterValueMapArg&) = delete;

  ParameterValueMapArg(ParameterValueMapArg&&) = default;
  ParameterValueMapArg& operator=(ParameterValueMapArg&&) = default;

  ParameterValueMapArg(const zetasql::ParameterValueMap& value, As intent)
      : TypedArg(value), intent_(intent) {}
  ParameterValueMapArg(zetasql::ParameterValueMap&& value, As intent)
      : TypedArg(value), intent_(intent) {}
  ParameterValueMapArg(std::unique_ptr<zetasql::ParameterValueMap> pointer, As intent)
      : TypedArg(std::move(pointer)), intent_(intent) {}

  virtual ~ParameterValueMapArg() = default;

  void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }

  As GetIntent() { return intent_; }

 private:
  As intent_;
};
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_ARGUMENT_H