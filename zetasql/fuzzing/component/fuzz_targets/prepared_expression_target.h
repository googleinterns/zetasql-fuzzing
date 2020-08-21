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

#ifndef ZETASQL_FUZZING_PREPARED_EXPRESSION_TARGET_H
#define ZETASQL_FUZZING_PREPARED_EXPRESSION_TARGET_H

#include "zetasql/fuzzing/component/fuzz_targets/fuzz_target.h"

namespace zetasql_fuzzer {

// Defines encapsulation of zetasql::PreparedExpression::ExecuteWithPositionalParams API
class PreparedExpressionTarget : public FuzzTarget {
 public:
  void Visit(SQLStringArg& sql) override;
  void Visit(ParameterValueMapArg& arg) override;
  void Execute() override;

 private:
  std::unique_ptr<std::string> sql_expression_;
  std::unique_ptr<zetasql::ParameterValueMap> columns_;
  std::unique_ptr<zetasql::ParameterValueMap> parameters_;
};

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_PREPARED_EXPRESSION_TARGET_H