//
// Copyright 2020 Google LLC.
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

#include <memory>
#include <string>
#include <tuple>
#include <google/protobuf/text_format.h>

#include "zetasql/fuzzing/protobuf/zetasql_expression_grammar.pb.h"
#include "zetasql/fuzzing/protobuf/internal/zetasql_expression_extractor.h"
#include "gtest/gtest.h"

using zetasql_expression_grammar::Expression;
using zetasql_expression_grammar::LiteralExpr;
using zetasql_expression_grammar::IntegerLiteral;
using zetasql_expression_grammar::NumericLiteral;
using zetasql_expression_grammar::CompoundExpr;
using zetasql_expression_grammar::BinaryOperation;
using parameter_grammar::Whitespace;
using zetasql_fuzzer::internal::ProtoExprExtractor;

namespace zetasql_fuzzer {
namespace {

using InvokeExtractCallback = std::function<void(ProtoExprExtractor&)>;
class ProtoExprExtractorTest
    : public ::testing::TestWithParam<
          std::tuple<InvokeExtractCallback, std::string>> {
 protected:
  ProtoExprExtractor extractor;
};

// Parameterized Test

TEST_P(ProtoExprExtractorTest, ExtractTest) {
  std::get<0>(GetParam())(extractor);
  EXPECT_EQ(extractor.Data(), std::get<1>(GetParam()));
}

template <typename ExprType>
InvokeExtractCallback ExtractableEmptyExpression() {
  return [](ProtoExprExtractor& extractor) {
    ExprType expression;
    extractor.Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
    EmptyExpressionTest, ProtoExprExtractorTest,
    ::testing::Values(
        std::make_tuple(ExtractableEmptyExpression<Expression>(), ""),
        std::make_tuple(ExtractableEmptyExpression<LiteralExpr>(), ""),
        std::make_tuple(ExtractableEmptyExpression<IntegerLiteral>(), ""),
        std::make_tuple(ExtractableEmptyExpression<CompoundExpr>(), "")));

template <typename ExprType>
InvokeExtractCallback ExtractableDefaultValue(const std::string& value) {
  return [value](ProtoExprExtractor& extractor) {
    ExprType expression;
    expression.mutable_default_value()->set_content(value);
    extractor.Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
    DefaultOneOfValueTest, ProtoExprExtractorTest,
    ::testing::Values(
        std::make_tuple(ExtractableDefaultValue<Expression>("default"),
                        "default"),
        std::make_tuple(ExtractableDefaultValue<LiteralExpr>("default_lit"),
                        "default_lit"),
        std::make_tuple(ExtractableDefaultValue<IntegerLiteral>("default_int"),
                        "default_int"),
        std::make_tuple(ExtractableDefaultValue<CompoundExpr>("default_expr"),
                        "default_expr")));

InvokeExtractCallback ExtractableStringLiteral(
    const std::string& value) {
  return [value](ProtoExprExtractor& extractor) {
    LiteralExpr expr;
    expr.set_string_literal(value);
    extractor.Extract(expr);
  };
}

INSTANTIATE_TEST_SUITE_P(
    StringLiteralTest, ProtoExprExtractorTest,
    ::testing::Values(std::make_tuple(ExtractableStringLiteral(""), "\"\""),
                      std::make_tuple(ExtractableStringLiteral("tEsT"), "\"tEsT\"")));

InvokeExtractCallback ExtractableBytesLiteral(
    const std::string& value) {
  return [value](ProtoExprExtractor& extractor) {
    LiteralExpr expr;
    expr.set_bytes_literal(value);
    extractor.Extract(expr);
  };
}

INSTANTIATE_TEST_SUITE_P(
    BytesLiteralTest, ProtoExprExtractorTest,
    ::testing::Values(
        std::make_tuple(ExtractableBytesLiteral(""), "B\"\""),
        std::make_tuple(ExtractableBytesLiteral("TeSt"), "B\"TeSt\""),
        std::make_tuple(ExtractableBytesLiteral("\x01\x02"), "B\"\x01\x02\"")));

InvokeExtractCallback ExtractableSpecialLiteral(const zetasql_expression_grammar::LiteralExpr_SpecialValue& value) {
  return [value](ProtoExprExtractor& extractor) {
    LiteralExpr expression;
    expression.set_special_literal(value);
    extractor.Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
    SpecialLiteralTest, ProtoExprExtractorTest,
    ::testing::Values(
        std::make_tuple(ExtractableSpecialLiteral(LiteralExpr::V_NULL), "NULL")));

template <IntegerLiteral::IntegerOneofCase IntegerType, typename T>
InvokeExtractCallback ExtractableIntegerLiteral(const T& value) {
  return [value](ProtoExprExtractor& extractor) {
    IntegerLiteral expression;
    switch (IntegerType) {
      case IntegerLiteral::kInt32Literal:
        expression.set_int32_literal(value);
        break;
      case IntegerLiteral::kUint32Literal:
        expression.set_uint32_literal(value);
        break;
      case IntegerLiteral::kInt64Literal:
        expression.set_int64_literal(value);
        break;
      case IntegerLiteral::kUint64Literal:
        expression.set_uint64_literal(value);
        break;
      default:
        assert(false && "IntegerType for IntegerLiteralTest is wrongly set up");
    }
    extractor.Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
  IntegerLiteralTest, ProtoExprExtractorTest,
  ::testing::Values(
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(1), "1"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(0), "0"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(google::protobuf::kint32max), "2147483647"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(google::protobuf::kint32min), "-2147483648"),

    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint32Literal>(1), "1"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint32Literal>(0), "0"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint32Literal>(google::protobuf::kuint32max), "4294967295"),

    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(1), "1"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(0), "0"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(google::protobuf::kint64max), "9223372036854775807"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(google::protobuf::kint64min), "-9223372036854775808"),

    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint64Literal>(1), "1"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint64Literal>(0), "0"),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint64Literal>(google::protobuf::kuint64max), "18446744073709551615")
  )
);

InvokeExtractCallback ExtractableNumeric(const std::string& value) {
  return [value](ProtoExprExtractor& extractor) {
    NumericLiteral expression;
    expression.set_value(value);
    extractor.Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
    NumericLiteralTest, ProtoExprExtractorTest,
    ::testing::Values(std::make_tuple(ExtractableNumeric("\xff\xff\xff\xff"),
                                      "NUMERIC '\xff\xff\xff\xff'")));

void InsertWhitespaceHelper(Whitespace& expression, const std::vector<Whitespace::Type>& value) {
  if (value.empty()) return;
  auto it = value.begin();
  expression.set_space(*it);
  auto end = value.end();
  for (++it; it != end; it++) {
    expression.add_additional(*it);
  }
}

InvokeExtractCallback ExtractableWhitespaces(const std::vector<Whitespace::Type>& value) {
  return [value](ProtoExprExtractor& extractor) {
    Whitespace expression;
    InsertWhitespaceHelper(expression, value);
    extractor.Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
    WhitespaceTest, ProtoExprExtractorTest,
    ::testing::Values(
        std::make_tuple(ExtractableWhitespaces({Whitespace::SPACE}), " "),
        std::make_tuple(ExtractableWhitespaces({Whitespace::SPACE, Whitespace::SPACE}), "  "),
        std::make_tuple(ExtractableWhitespaces({Whitespace::TAB, Whitespace::SPACE}), "\t "),
        std::make_tuple(ExtractableWhitespaces({Whitespace::TAB, Whitespace::SPACE, Whitespace::BACKSPACE}), "\t \b"),
        std::make_tuple(ExtractableWhitespaces({Whitespace::TAB, Whitespace::SPACE, Whitespace::BACKSPACE, Whitespace::NEWLINE}), "\t \b\n")
    )
);

InvokeExtractCallback ExtractableParenthesis(
    const std::string& value, bool parenthesized,
    const std::vector<Whitespace::Type>& leading_space,
    const std::vector<Whitespace::Type>& trailing_space) {
  return [value, parenthesized, leading_space, trailing_space](ProtoExprExtractor& extractor) {
    Expression expr;
    expr.mutable_default_value()->set_content(value);
    expr.set_parenthesized(parenthesized);
    InsertWhitespaceHelper(*expr.mutable_leading_pad(), leading_space);
    InsertWhitespaceHelper(*expr.mutable_trailing_pad(), trailing_space);
    extractor.Extract(expr);
  };
}

INSTANTIATE_TEST_SUITE_P(
    ParenthesisTest, ProtoExprExtractorTest,
    ::testing::Values(
      std::make_tuple(ExtractableParenthesis("asdf", true, {Whitespace::SPACE}, {Whitespace::TAB}), "( asdf\t)"),
      std::make_tuple(ExtractableParenthesis("asdf", false, {Whitespace::SPACE}, {Whitespace::TAB}), "asdf")
    )
);

TEST_F(ProtoExprExtractorTest, BinaryExprTest) {
  BinaryOperation binary;
  binary.mutable_lhs()->mutable_default_value()->set_content("TeSt");
  binary.mutable_left_pad()->set_space(Whitespace::TAB);
  binary.set_op(BinaryOperation::PLUS);
  binary.mutable_right_pad()->set_space(Whitespace::NEWLINE);
  binary.mutable_rhs()
      ->mutable_literal()
      ->mutable_integer_literal()
      ->set_int32_literal(1);

  extractor.Extract(binary);
  EXPECT_EQ(extractor.Data(), "TeSt\t+\n1");
}

TEST_F(ProtoExprExtractorTest, CompoundExprTest) {
  Expression expr;
  expr.mutable_expr()->mutable_binary_operation()
    ->set_op(BinaryOperation::MULTIPLY);
  expr.mutable_expr()->mutable_binary_operation()
    ->mutable_lhs()->mutable_literal()->set_string_literal("tEsT");

  auto subexpr = std::make_unique<Expression>();
  subexpr->mutable_expr()->mutable_binary_operation()
    ->set_op(BinaryOperation::MINUS);
  subexpr->mutable_expr()->mutable_binary_operation()
    ->mutable_lhs()->mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(google::protobuf::kuint64max);
  subexpr->mutable_expr()->mutable_binary_operation()
    ->mutable_rhs()->mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(google::protobuf::kint32min);

  expr.mutable_expr()->mutable_binary_operation()
    ->set_allocated_rhs(subexpr.release()); 
  extractor.Extract(expr);
  EXPECT_EQ(extractor.Data(), "\"tEsT\" * 18446744073709551615 - -2147483648");
}

TEST_F(ProtoExprExtractorTest, IncrementalTest) {
  Expression expr;
  ProtoExprExtractor extractor;

  expr.mutable_literal()->mutable_integer_literal()->set_int32_literal(1);
  extractor.Extract(expr);

  NumericLiteral num_expr;
  num_expr.set_value("asdfas");
  extractor.Extract(num_expr);
  EXPECT_EQ(extractor.Data(), "1NUMERIC 'asdfas'");
}

}  // namespace
}  // namespace zetasql_fuzzer