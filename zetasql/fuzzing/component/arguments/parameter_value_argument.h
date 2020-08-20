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

#ifndef ZETASQL_FUZZING_PARAMETER_VALUE_ARGUMENT_H
#define ZETASQL_FUZZING_PARAMETER_VALUE_ARGUMENT_H

#include "zetasql/fuzzing/component/arguments/argument.h"
#include "zetasql/public/evaluator_base.h"

namespace zetasql_fuzzer {

enum ParameterValueAs { COLUMNS, PARAMETERS };

template <typename ArgType>
class ParameterValueContainerArg : public TypedArg<ArgType> {
 public:
  ParameterValueContainerArg() = delete;
  ParameterValueContainerArg(const ParameterValueContainerArg&) = delete;
  ParameterValueContainerArg& operator=(const ParameterValueContainerArg&) = delete;

  ParameterValueContainerArg(ParameterValueContainerArg&&) = default;
  ParameterValueContainerArg& operator=(ParameterValueContainerArg&&) = default;

  ParameterValueContainerArg(const ArgType& value, ParameterValueAs intent)
      : TypedArg<ArgType>(value), intent_(intent) {}
  ParameterValueContainerArg(ArgType&& value, ParameterValueAs intent)
      : TypedArg<ArgType>(value), intent_(intent) {}
  ParameterValueContainerArg(std::unique_ptr<ArgType> pointer, ParameterValueAs intent)
      : TypedArg<ArgType>(std::move(pointer)), intent_(intent) {}

  virtual ~ParameterValueContainerArg() = default;

  ParameterValueAs GetIntent() { return intent_; }

 private:
  ParameterValueAs intent_;
};

class ParameterValueMapArg : public ParameterValueContainerArg<zetasql::ParameterValueMap> {
 public:
  using ParameterValueContainerArg::ParameterValueContainerArg;
  virtual ~ParameterValueMapArg() = default;
  void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }
};

class ParameterValueListArg : public ParameterValueContainerArg<zetasql::ParameterValueList> {
 public:
  using ParameterValueContainerArg::ParameterValueContainerArg;
  virtual ~ParameterValueListArg() = default;
  void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }
};
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_PARAMETER_VALUE_ARGUMENT_H