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
//'

#include "zetasql/fuzzing/protobuf/internal/zetasql_expression_extractor.h"

#include "zetasql/base/logging.h"

using parameter_grammar::Identifier;
using parameter_grammar::IntegerLiteral;
using parameter_grammar::Literal;
using parameter_grammar::NumericLiteral;
using parameter_grammar::Value;
using parameter_grammar::Whitespace;
using zetasql_expression_grammar::BinaryOperation;
using zetasql_expression_grammar::CompoundExpr;
using zetasql_expression_grammar::Expression;

namespace zetasql_fuzzer {
namespace internal {

inline void SQLExprExtractor::Quote(const std::string& content,
                                      const std::string& quote) {
  Append(quote);
  Append(content);
  Append(quote);
}

void SQLExprExtractor::Extract(const Expression& expr) {
  using ExprType = Expression::ExprOneofCase;
  if (expr.parenthesized()) {
    Append("(");
    if (expr.has_leading_pad()) {
      Extract(expr.leading_pad());
    }
  }

  switch (expr.expr_oneof_case()) {
    case ExprType::kValue:
      Extract(expr.value());
      break;
    case ExprType::kExpr:
      Extract(expr.expr());
      break;
    default:
      ExtractDefault(expr);
      break;
  }

  if (expr.parenthesized()) {
    if (expr.has_trailing_pad()) {
      Extract(expr.trailing_pad());
    }
    Append(")");
  }
}

void SQLExprExtractor::Extract(const Identifier& id) {
  switch (id.type()) {
    case Identifier::COLUMN:
      break;
    case Identifier::PARAMETER:
      Append("@");
      break;
    default:
      LOG(FATAL) <<
          "Unhandled Identifier Formatting. Please update SQLExprExtractor "
          "implementaion";
  }
  Append(id.name());
}

void SQLExprExtractor::Extract(const Value& value) {
  if (value.has_as_variable()) {
    return Extract(value.as_variable());
  }

  return Extract(value.literal());
}

void SQLExprExtractor::Extract(const Literal& literal) {
  switch (literal.literal_oneof_case()) {
    case Literal::kNullLiteral:
      return Append("NULL");
    case Literal::kBoolLiteral:
      return Append(literal.bool_literal() ? "TRUE" : "FALSE");
    case Literal::kBytesLiteral:
      Append("B");
      return Quote(literal.bytes_literal(), "\"");
    case Literal::kStringLiteral:
      return Quote(literal.string_literal(), "\"");
    case Literal::kIntegerLiteral:
      return Extract(literal.integer_literal());
    case Literal::kNumericLiteral:
      return Extract(literal.numeric_literal());
    default:
      return ExtractDefault(literal);
  }
}

void SQLExprExtractor::Extract(const IntegerLiteral& integer) {
  using IntergerType = IntegerLiteral::IntegerOneofCase;
  switch (integer.integer_oneof_case()) {
    case IntergerType::kInt32Literal:
      return Append(integer.int32_literal());
    case IntergerType::kUint32Literal:
      return Append(integer.uint32_literal());
    case IntergerType::kInt64Literal:
      return Append(integer.int64_literal());
    case IntergerType::kUint64Literal:
      return Append(integer.uint64_literal());
    default:
      return ExtractDefault(integer);
  }
}

void SQLExprExtractor::Extract(const NumericLiteral& numeric) {
  Append("NUMERIC ");
  return Quote(numeric.value(), "'");
}

void SQLExprExtractor::Extract(const CompoundExpr& comp_expr) {
  using CompoundExprType = CompoundExpr::CompoundOneofCase;
  switch (comp_expr.compound_oneof_case()) {
    case CompoundExprType::kBinaryOperation:
      return Extract(comp_expr.binary_operation());
    default:
      return ExtractDefault(comp_expr);
  }
}

using zetasql_expression_grammar::BinaryOperation_Operator;
inline void SQLExprExtractor::ExtractBinaryOperator(
    const BinaryOperation_Operator binary) {
  switch (binary) {
    case BinaryOperation::PLUS:
      return Append("+");
    case BinaryOperation::MINUS:
      return Append("-");
    case BinaryOperation::MULTIPLY:
      return Append("*");
    case BinaryOperation::DIVIDE:
      return Append("/");
    default:
      LOG(FATAL) <<
          "Unhandled Binary Operation. Please update Extractor implementation";
  }
}

void SQLExprExtractor::Extract(const BinaryOperation& binary_operation) {
  using zetasql_expression_grammar::BinaryOperation_Operator;
  Extract(binary_operation.lhs());
  Extract(binary_operation.left_pad());
  ExtractBinaryOperator(binary_operation.op());
  Extract(binary_operation.right_pad());
  Extract(binary_operation.rhs());
}

using parameter_grammar::Whitespace_Type;
inline void SQLExprExtractor::ExtractWhitespaceCharacter(
    const Whitespace_Type whitespace) {
  switch (whitespace) {
    case Whitespace::SPACE:
      return Append(" ");
    case Whitespace::BACKSPACE:
      return Append("\b");
    case Whitespace::TAB:
      return Append("\t");
    case Whitespace::NEWLINE:
      return Append("\n");
    default:
      LOG(FATAL) <<
          "Unhandled Whitespace Character. Please update Extractor "
          "implementation";
  }
}

void SQLExprExtractor::Extract(const Whitespace& whitespaces) {
  using parameter_grammar::Whitespace_Type;
  ExtractWhitespaceCharacter(whitespaces.space());
  for (const auto& additional_space : whitespaces.additional()) {
    ExtractWhitespaceCharacter(static_cast<Whitespace_Type>(additional_space));
  }
}

}  // namespace internal
}  // namespace zetasql_fuzzer