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

#include "zetasql/fuzzing/component/fuzz_targets/prepared_expression_target.h"

#include "zetasql/base/logging.h"
#include "zetasql/fuzzing/component/arguments/argument.h"
#include "zetasql/fuzzing/component/arguments/parameter_value_argument.h"
#include "zetasql/public/evaluator.h"

namespace zetasql_fuzzer {

void PreparedExpressionTarget::Visit(SQLStringArg& arg) {
  sql_expression_ = arg.Release().ValueOrDie();
}

void PreparedExpressionTarget::Visit(ParameterValueMapArg& arg) {
  switch (arg.GetIntent()) {
    case ParameterValueAs::COLUMNS:
      columns_ = arg.Release().ValueOrDie();
      return;
    case ParameterValueAs::PARAMETERS:
      parameters_ = arg.Release().ValueOrDie();
      return;
    default:
      LOG(FATAL)
          << "Unhandled ParameterValueMapArg in PreparedExpressionTarget";
  }
}

void PreparedExpressionTarget::Execute() {
  if (!sql_expression_) {
    LOG(FATAL) << "SQL expression not found";
  }
  zetasql::PreparedExpression expression(*sql_expression_);
  expression.Execute(GetOrDefault(columns_), GetOrDefault(parameters_));
}

}  // namespace zetasql_fuzzer