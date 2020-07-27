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

#include "zetasql/fuzzing/protobuf/zetasql_expression_extractor.h"

#define EXTRACT_DEFAULT(var) Append(var.default_value().content())

namespace zetasql_fuzzer {

inline void ProtoExprExtractor::Quote(const std::string& content, const std::string& quote) {
  Append(quote);
  Append(content);
  Append(quote);
}

std::string ProtoExprExtractor::Release() {
  std::string released(std::move(builder));
  builder.clear();
  return released;
}

void ProtoExprExtractor::Extract(const Expression& expr) {
  using ExprType = Expression::ExprOneofCase;
  if (expr.parenthesized()) {
    Append("(");
    if (expr.has_leading_pad()) {
      Extract(expr.leading_pad());
    }
  }
  
  switch (expr.expr_oneof_case()) {
    case ExprType::kLiteral:
      Extract(expr.literal());
      break;
    case ExprType::kExpr:
      Extract(expr.expr());
      break;
    default:
      EXTRACT_DEFAULT(expr);
      break;
  }

  if (expr.parenthesized()) {
    if (expr.has_trailing_pad()) {
      Extract(expr.trailing_pad());
    }
    Append(")");
  }
}

void ProtoExprExtractor::Extract(const LiteralExpr& literal) {
  using LitExprType = LiteralExpr::LiteralOneofCase;
  switch (literal.literal_oneof_case()) {
    case LitExprType::kSpecialLiteral:
      switch (literal.special_literal()) {
        case LiteralExpr::V_NULL:
          return Append("NULL");
        default:
          Exit("Undefined Special Literal");
      }
    case LitExprType::kBoolLiteral:
      return Append(literal.bool_literal() ? "TRUE" : "FALSE");
    case LitExprType::kBytesLiteral:
      Append("B");
      return Quote(literal.bytes_literal(), "\"");
    case LitExprType::kStringLiteral:
      return Quote(literal.string_literal(), "\"");
    case LitExprType::kIntegerLiteral:
      return Extract(literal.integer_literal());
    case LitExprType::kNumericLiteral:
      return Extract(literal.numeric_literal());
    default:
      return EXTRACT_DEFAULT(literal);
  }
}

void ProtoExprExtractor::Extract(const IntegerLiteral& integer) {
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
      return EXTRACT_DEFAULT(integer);
  }
}

void ProtoExprExtractor::Extract(const NumericLiteral& numeric) {
  Append("NUMERIC ");
  return Quote(numeric.value(), "'");
}

void ProtoExprExtractor::Extract(const CompoundExpr& comp_expr) {
  using CompoundExprType = CompoundExpr::CompoundOneofCase;
  switch (comp_expr.compound_oneof_case()) {
    case CompoundExprType::kBinaryOperation:
      return Extract(comp_expr.binary_operation());
    default:
      return EXTRACT_DEFAULT(comp_expr);
  }
}

void ProtoExprExtractor::Extract(const BinaryOperation& binary_operation) {
  using zetasql_expression_grammar::BinaryOperation_Operator;
  const static std::map<BinaryOperation_Operator, std::string> operators{
      {BinaryOperation::PLUS, "+"},
      {BinaryOperation::MINUS, "-"},
      {BinaryOperation::MULTIPLY, "*"},
      {BinaryOperation::DIVIDE, "/"},
  };
  Extract(binary_operation.lhs());
  Extract(binary_operation.left_pad());
  TryCatch([&] { Append(operators.at(binary_operation.op())); });
  Extract(binary_operation.right_pad());
  Extract(binary_operation.rhs());
}

void ProtoExprExtractor::Extract(const Whitespace& whitespace) {
  using parameter_grammar::Whitespace_Type;
  const static std::map<Whitespace_Type, std::string> whitespaces{
      {Whitespace::SPACE, " "},
      {Whitespace::BACKSPACE, "\b"},
      {Whitespace::TAB, "\t"},
      {Whitespace::NEWLINE, "\n"},
  };
  TryCatch([&] { Append(whitespaces.at(whitespace.space())); });
  for (const auto& additional_space : whitespace.additional()) {
    TryCatch([&] {
      Append(whitespaces.at(static_cast<Whitespace_Type>(additional_space)));
    });
  }
}

}  // namespace zetasql_fuzzer