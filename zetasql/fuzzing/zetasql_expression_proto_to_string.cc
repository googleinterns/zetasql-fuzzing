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

#include <string>

#include "zetasql/fuzzing/common.h"
#include "zetasql/fuzzing/zetasql_expression_grammar.pb.h"

using namespace zetasql_expression_grammar;

namespace zetasql_fuzzer {

std::string HandleDefault() {
  return "0";
}

// Forward declaration
CONV_FN(Expression, expr);

CONV_FN(LiteralExpr, lit_expr);
CONV_FN(IntegerLiteral, integer);
CONV_FN(NumericLiteral, numeric);

CONV_FN(CompoundExpr, comp_expr);
CONV_FN(AdditiveOperation, additive);
CONV_FN(MultiplicativeOperation, multiplicative);

CONV_FN(Expression, expr) {
  using ExprType = Expression::ExprOneofCase;
  switch (expr.expr_oneof_case()) {
    case ExprType::kLiteral:
      return LiteralExprToString(expr.literal());
    case ExprType::kExpr:
      return CompoundExprToString(expr.expr());
    default:
      return HandleDefault();
  }
}

CONV_FN(LiteralExpr, literal) {
  using LitExprType = LiteralExpr::LiteralOneofCase;
  std::string ret;
  switch (literal.literal_oneof_case()) {
    case LitExprType::kSpecialLiteral:
      switch (literal.special_literal()) {
        case LiteralExpr::V_NULL:
          return "NULL";
        default:
          std::abort();
      }
    case LitExprType::kBoolLiteral:
      return literal.bool_literal() ? "TRUE" : "FALSE";
    case LitExprType::kBytesLiteral:
      return literal.bytes_literal();
    case LitExprType::kStringLiteral:
      return literal.string_literal();
    case LitExprType::kIntegerLiteral:
      return IntegerLiteralToString(literal.integer_literal());
    case LitExprType::kNumericLiteral:
      return NumericLiteralToString(literal.numeric_literal());
    default:
      return HandleDefault();
  }
}

CONV_FN(IntegerLiteral, integer) {
  using IntergerType = IntegerLiteral::IntegerOneofCase;
  using std::to_string;
  switch (integer.integer_oneof_case()) {
    case IntergerType::kInt32Literal:
      return to_string(integer.int32_literal());
    case IntergerType::kUint32Literal:
      return to_string(integer.uint32_literal());
    case IntergerType::kInt64Literal:
      return to_string(integer.int64_literal());
    case IntergerType::kUint64Literal:
      return to_string(integer.uint64_literal());
    default:
      return HandleDefault();
  }
}

CONV_FN(NumericLiteral, numeric) {
  return numeric.value();
};

CONV_FN(CompoundExpr, comp_expr) {
  using CompoundExprType = CompoundExpr::CompoundOneofCase;
  switch (comp_expr.compound_oneof_case()) {
    case CompoundExprType::kAdditive:
      return AdditiveOperationToString(comp_expr.additive());
    case CompoundExprType::kMultiplicative:
      return MultiplicativeOperationToString(comp_expr.multiplicative());
    default:
      return HandleDefault();
  }
};

CONV_FN(AdditiveOperation, additive) {
  std::string op;
  if (additive.operator_() == AdditiveOperation::PLUS) {
    op = " + ";
  } else { // if additive.operator_() == AdditiveOperation::MINUS
    op = " - ";
  }
  return ExpressionToString(additive.lhs()) + op + ExpressionToString(additive.rhs());
}

CONV_FN(MultiplicativeOperation, multiplicative) {
  std::string op;
  if (multiplicative.operator_() == MultiplicativeOperation::MULTIPLY) {
    op = " * ";
  } else { // if multiplicative.operator_() == AdditiveOperation::DIVIDE
    op = " / ";
  }
  return ExpressionToString(multiplicative.lhs()) + op + ExpressionToString(multiplicative.rhs());
}

} //name space zetasql_fuzzer