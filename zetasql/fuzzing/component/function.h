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

#ifndef ZETASQL_FUZZING_FUNCTION_H
#define ZETASQL_FUZZING_FUNCTION_H

#include <memory>
#include "zetasql/public/evaluator_base.h"

#include "zetasql/fuzzing/component/argument.h"

namespace zetasql_fuzzer {

class Function {
 public:
  template <typename T>
  void Visit(const PositionalArg<T>& arg) {
    std::cerr << "Not Implemented" << std::endl;
  }
  virtual void Visit(const PositionalArg<std::string>& arg) { Visit<>(arg); }
  virtual void Visit(const PositionalArg<zetasql::ParameterValueMap>& arg) {
    Visit<>(arg);
  }
  virtual void Execute() = 0;
};

class PreparedExpressionFunction : public Function {
 public:
  void Visit(const PositionalArg<std::string>& arg) override;
  void Visit(const PositionalArg<zetasql::ParameterValueMap>& arg) override;
  void Execute() override;

 private:
  const std::shared_ptr<std::string> sql_expression;
  const std::shared_ptr<zetasql::ParameterValueMap> columns;
  const std::shared_ptr<zetasql::ParameterValueMap> parameters;
};

}  // namespace zetasql_fuzzer

#endif  //ZETASQL_FUZZING_FUNCTION_H