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

class ProtoExpression {
 public:
  virtual void Accept(ProtoExprExtractor& extractor) = 0;
  virtual ::google::protobuf::Message* GetExpression() = 0;
};

using ProtoExpressionCreator = std::function<std::unique_ptr<ProtoExpression>(void)>;
template <typename MessageType>
class TypedExpression : public ProtoExpression {
 public:
  static std::unique_ptr<ProtoExpression> Create() {
    return std::unique_ptr<ProtoExpression>(new TypedExpression<MessageType>);
  }
  virtual void Accept(ProtoExprExtractor& extractor) override {
    extractor.Extract(container);
  }
  virtual ::google::protobuf::Message* GetExpression() {
    return &container;
  }

 private:
  MessageType container;
};

}  // namespace

namespace internal {

class ProtoExprExtractorTest
    : public ::testing::TestWithParam<
          std::tuple<ProtoExpressionCreator, std::string, std::string>> {
 protected:
  ProtoExprExtractor extractor;
  std::unique_ptr<ProtoExpression> expression;

  const std::string& GetExpected() {
    return std::get<2>(GetParam());
  }
};

TEST_P(ProtoExprExtractorTest, ParamTest) {
  expression = std::get<0>(GetParam())();
  if (!::google::protobuf::TextFormat::ParseFromString(
          std::get<1>(GetParam()), expression->GetExpression())) {
    std::cerr << "Error Parsing Protobuf Message" << std::endl;
    std::abort();
  }
  expression->Accept(extractor);
  EXPECT_EQ(extractor.Release(), GetExpected());
}

INSTANTIATE_TEST_SUITE_P(
    ParamTest, ProtoExprExtractorTest,
    ::testing::Values(
        std::make_tuple<ProtoExpressionCreator, std::string, std::string>(
            TypedExpression<Expression>::Create, R"expr(default_value {
  content: "a"
}
parenthesized: false)expr",
            "a")));

TEST_F(ProtoExprExtractorTest, ExtractorReleaseTest) {
  std::string arbitrary("asdAgwegfGgw11");
  ProtoExprExtractor extractor;

  EXPECT_EQ(extractor.Release(), "");
  extractor.Append(arbitrary);
  EXPECT_EQ(arbitrary, "asdAgwegfGgw11");
  EXPECT_EQ(extractor.Release(), "asdAgwegfGgw11");
  EXPECT_EQ(extractor.Release(), "");
}

TEST_F(ProtoExprExtractorTest, UninitializedOneOfExprTest) {
  ProtoExprExtractor extractor;

  Expression expr;
  std::string s;
  extractor.Extract(expr);
  EXPECT_EQ(extractor.Release(), "");

  expr.mutable_default_value()->set_content("default");
  extractor.Extract(expr);
  EXPECT_EQ(extractor.Release(), "default");

  LiteralExpr lit_expr;
  extractor.Extract(lit_expr);
  EXPECT_EQ(extractor.Release(), "");

  lit_expr.mutable_default_value()->set_content("default_lit");
  extractor.Extract(lit_expr);
  EXPECT_EQ(extractor.Release(), "default_lit");

  IntegerLiteral int_expr;
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "");

  int_expr.mutable_default_value()->set_content("default_int");
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "default_int");

  CompoundExpr comp_expr;
  extractor.Extract(comp_expr);
  EXPECT_EQ(extractor.Release(), "");

  comp_expr.mutable_default_value()->set_content("default_expr");
  extractor.Extract(comp_expr);
  EXPECT_EQ(extractor.Release(), "default_expr");
}

TEST_F(ProtoExprExtractorTest, SpecialLiteralTest) {
  using zetasql_expression_grammar::LiteralExpr_SpecialValue;
  LiteralExpr lit_expr;
  ProtoExprExtractor extractor;
  lit_expr.set_special_literal(LiteralExpr::V_NULL);
  extractor.Extract(lit_expr);
  EXPECT_EQ(extractor.Release(), "NULL");
  // lit_expr.set_special_literal(static_cast<LiteralExpr_SpecialValue>(100));
  // extractor.Extract(lit_expr);
  // EXPECT_DEATH(extractor.Extract(lit_expr));
}

TEST_F(ProtoExprExtractorTest, StringLiteralTest) {
  LiteralExpr str_expr;
  ProtoExprExtractor extractor;

  str_expr.set_string_literal("");
  extractor.Extract(str_expr);
  EXPECT_EQ(extractor.Release(), "\"\"");

  str_expr.set_string_literal("tEsT");
  extractor.Extract(str_expr);
  EXPECT_EQ(extractor.Release(), "\"tEsT\"");
}

TEST_F(ProtoExprExtractorTest, BytesLiteralTest) {
  LiteralExpr lit_expr;
  ProtoExprExtractor extractor;
  lit_expr.mutable_bytes_literal();
  extractor.Extract(lit_expr);
  EXPECT_EQ(extractor.Release(), "B\"\"");

  lit_expr.set_bytes_literal("");
  extractor.Extract(lit_expr);
  EXPECT_EQ(extractor.Release(), "B\"\"");

  lit_expr.set_bytes_literal("TeSt");
  extractor.Extract(lit_expr);
  EXPECT_EQ(extractor.Release(), "B\"TeSt\"");

  lit_expr.set_bytes_literal("\x01\x02");
  extractor.Extract(lit_expr);
  EXPECT_EQ(extractor.Release(), "B\"\x01\x02\"");
}

TEST_F(ProtoExprExtractorTest, IntegerLiteralTest) {
  IntegerLiteral int_expr;
  ProtoExprExtractor extractor;
  int_expr.set_int32_literal(1);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "1");
  int_expr.set_int32_literal(0);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "0");
  int_expr.set_int32_literal(google::protobuf::kint32max);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "2147483647");
  int_expr.set_int32_literal(google::protobuf::kint32min);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "-2147483648");

  int_expr.set_uint32_literal(1);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "1");
  int_expr.set_uint32_literal(0);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "0");
  int_expr.set_uint32_literal(google::protobuf::kuint32max);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "4294967295");

  int_expr.set_int64_literal(1);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "1");
  int_expr.set_int64_literal(0);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "0");
  int_expr.set_int64_literal(google::protobuf::kint64max);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "9223372036854775807");
  int_expr.set_int64_literal(google::protobuf::kint64min);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "-9223372036854775808");

  int_expr.set_uint64_literal(1);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "1");
  int_expr.set_uint64_literal(0);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "0");
  int_expr.set_uint64_literal(google::protobuf::kuint64max);
  extractor.Extract(int_expr);
  EXPECT_EQ(extractor.Release(), "18446744073709551615");
}

TEST_F(ProtoExprExtractorTest, NumericLiteralTest) {
  NumericLiteral num_expr;
  ProtoExprExtractor extractor;
  num_expr.set_value("\xff\xff\xff\xff");
  extractor.Extract(num_expr);
  EXPECT_EQ(extractor.Release(), "NUMERIC '\xff\xff\xff\xff'");
}

TEST_F(ProtoExprExtractorTest, WhitespaceExprTest) {
  Whitespace whitespace;
  whitespace.set_space(Whitespace::SPACE);

  ProtoExprExtractor extractor;
  extractor.Extract(whitespace);
  EXPECT_EQ(extractor.Release(), " ");

  whitespace.add_additional(Whitespace::SPACE);
  extractor.Extract(whitespace);
  EXPECT_EQ(extractor.Release(), "  ");

  whitespace.set_space(Whitespace::TAB);
  extractor.Extract(whitespace);
  EXPECT_EQ(extractor.Release(), "\t ");

  whitespace.add_additional(Whitespace::BACKSPACE);
  extractor.Extract(whitespace);
  EXPECT_EQ(extractor.Release(), "\t \b");

  whitespace.add_additional(Whitespace::NEWLINE);
  extractor.Extract(whitespace);
  EXPECT_EQ(extractor.Release(), "\t \b\n");
}

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

  ProtoExprExtractor extractor;
  extractor.Extract(binary);
  EXPECT_EQ(extractor.Release(), "TeSt\t+\n1");
}

TEST_F(ProtoExprExtractorTest, CompoundExprTest) {
  Expression expr;
  ProtoExprExtractor extractor;

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
  EXPECT_EQ(extractor.Release(), "\"tEsT\" * 18446744073709551615 - -2147483648");
}

TEST_F(ProtoExprExtractorTest, IncrementalTest) {
  Expression expr;
  ProtoExprExtractor extractor;

  expr.mutable_literal()->mutable_integer_literal()->set_int32_literal(1);
  extractor.Extract(expr);

  NumericLiteral num_expr;
  num_expr.set_value("asdfas");
  extractor.Extract(num_expr);
  EXPECT_EQ(extractor.Release(), "1NUMERIC 'asdfas'");
}

TEST_F(ProtoExprExtractorTest, ParenthesesTest) {
  Expression expr;
  ProtoExprExtractor extractor;

  expr.mutable_literal()->mutable_numeric_literal()->set_value("asdf");
  expr.set_parenthesized(true);
  extractor.Extract(expr);
  EXPECT_EQ(extractor.Release(), "(NUMERIC 'asdf')");

  expr.mutable_leading_pad()->set_space(Whitespace::SPACE);
  extractor.Extract(expr);
  EXPECT_EQ(extractor.Release(), "( NUMERIC 'asdf')");

  expr.mutable_trailing_pad()->set_space(Whitespace::NEWLINE);
  extractor.Extract(expr);
  EXPECT_EQ(extractor.Release(), "( NUMERIC 'asdf'\n)");
}

}  // namespace
}  // namespace zetasql_fuzzer