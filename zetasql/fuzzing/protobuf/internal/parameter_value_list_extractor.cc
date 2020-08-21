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

#include "zetasql/fuzzing/protobuf/internal/parameter_value_list_extractor.h"

#include "zetasql/fuzzing/protobuf/internal/literal_value_extractor.h"

using zetasql_expression_grammar::BinaryOperation;
using zetasql_expression_grammar::CompoundExpr;
using zetasql_expression_grammar::Expression;

namespace zetasql_fuzzer {
namespace internal {

void ParameterValueListExtractor::Extract(const zetasql_expression_grammar::Expression& expr) {
  switch (expr.expr_oneof_case()) {
    case Expression::kValue:
      return Extract(expr.value());
    case Expression::kExpr:
      return Extract(expr.expr());
    default:
      return;
  }
}

void ParameterValueListExtractor::Extract(const parameter_grammar::Value& value) {
  if (value.has_as_variable() && extract_type_ == value.as_variable().type()) {
      // Push back everything regardless of Value validity to preserve positional order
      builder_.push_back(LiteralValueExtractor::Extract(value.literal()));
  }
}

void ParameterValueListExtractor::Extract(const zetasql_expression_grammar::CompoundExpr& comp_expr) {
  switch (comp_expr.compound_oneof_case()) {
    case CompoundExpr::kBinaryOperation:
      return Extract(comp_expr.binary_operation());
    default:
      return;
  }
}

void ParameterValueListExtractor::Extract(const zetasql_expression_grammar::BinaryOperation& binary_operation) {
  Extract(binary_operation.lhs());
  Extract(binary_operation.rhs());
}

}  // namespace internal
}  // namespace zetasql_fuzzer