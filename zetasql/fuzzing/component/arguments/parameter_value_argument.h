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

class ParameterValueMapArg : public TypedArg<zetasql::ParameterValueMap> {
 public:
  ParameterValueMapArg() = delete;
  ParameterValueMapArg(const ParameterValueMapArg&) = delete;
  ParameterValueMapArg& operator=(const ParameterValueMapArg&) = delete;

  ParameterValueMapArg(ParameterValueMapArg&&) = default;
  ParameterValueMapArg& operator=(ParameterValueMapArg&&) = default;

  ParameterValueMapArg(const zetasql::ParameterValueMap& value, ParameterValueAs intent)
      : TypedArg(value), intent_(intent) {}
  ParameterValueMapArg(zetasql::ParameterValueMap&& value, ParameterValueAs intent)
      : TypedArg(value), intent_(intent) {}
  ParameterValueMapArg(std::unique_ptr<zetasql::ParameterValueMap> pointer, ParameterValueAs intent)
      : TypedArg(std::move(pointer)), intent_(intent) {}

  virtual ~ParameterValueMapArg() = default;

  void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }

  ParameterValueAs GetIntent() { return intent_; }

 private:
  ParameterValueAs intent_;
};
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_PARAMETER_VALUE_ARGUMENT_H