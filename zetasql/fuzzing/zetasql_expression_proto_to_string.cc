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

#include "zetasql/fuzzing/zetasql_expression_grammar.pb.h"

using zetasql_expression_grammar::Expression;
using zetasql_expression_grammar::LiteralExpr;
using zetasql_expression_grammar::IntegerLiteral;
using zetasql_expression_grammar::NumericLiteral;
using zetasql_expression_grammar::CompoundExpr;
using zetasql_expression_grammar::BinaryOperation;

#define TO_STRING(TYPE, VAR_NAME) std::string TYPE##ToString(const TYPE& VAR_NAME)

namespace zetasql_fuzzer {

// Forward declaration
TO_STRING(Expression, expr);

TO_STRING(LiteralExpr, lit_expr);
TO_STRING(IntegerLiteral, integer);
TO_STRING(NumericLiteral, numeric);

TO_STRING(CompoundExpr, comp_expr);
TO_STRING(BinaryOperation, operation);

inline void HandleUndefined(const std::string& error) {
  std::cerr << error << std::endl;
  std::abort();
}

inline std::string HandleDefault() {
  return "0";
}

inline std::string Padded(const std::string& s) {
  return " " + s + " ";
}


TO_STRING(Expression, expr) {
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

TO_STRING(LiteralExpr, literal) {
  using LitExprType = LiteralExpr::LiteralOneofCase;
  switch (literal.literal_oneof_case()) {
    case LitExprType::kSpecialLiteral:
      switch (literal.special_literal()) {
        case LiteralExpr::V_NULL:
          return "NULL";
        default:
          HandleUndefined("Undefined Special Literal");
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

TO_STRING(IntegerLiteral, integer) {
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

TO_STRING(NumericLiteral, numeric) {
  return numeric.value();
};

TO_STRING(CompoundExpr, comp_expr) {
  using CompoundExprType = CompoundExpr::CompoundOneofCase;
  switch (comp_expr.compound_oneof_case()) {
    case CompoundExprType::kBinaryOperation:
      return BinaryOperationToString(comp_expr.binary_operation());
    default:
      return HandleDefault();
  }
};

inline std::string GetBinaryOperator(zetasql_expression_grammar::BinaryOperation_Operator op) {
  switch (op) {
  case BinaryOperation::PLUS:
    return "+";
  case BinaryOperation::MINUS:
    return "-";
  case BinaryOperation::MULTIPLY:
    return "*";
  case BinaryOperation::DIVIDE:
    return "/";
  default:
    HandleUndefined("Undefined Binary Operator");
  }
}

TO_STRING(BinaryOperation, binary_operation) {
  std::string operator_str = GetBinaryOperator(binary_operation.op());
  return ExpressionToString(binary_operation.lhs()) + 
          Padded(operator_str) + 
          ExpressionToString(binary_operation.rhs());
}

}  //name space zetasql_fuzzer