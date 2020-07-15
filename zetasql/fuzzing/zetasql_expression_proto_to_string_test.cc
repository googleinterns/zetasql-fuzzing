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

#include "zetasql/fuzzing/zetasql_expression_grammar.pb.h"
#include "zetasql/fuzzing/zetasql_expression_proto_to_string.h"
#include "gtest/gtest.h"

using zetasql_expression_grammar::Expression;

namespace zetasql_fuzzer {
namespace {

TEST(ProtoToStringTest, UninitializedOneOfExprTest) {
  Expression expr;
  EXPECT_EQ(ExpressionToString(expr), "0");

  expr.mutable_literal();
  EXPECT_EQ(ExpressionToString(expr), "0");

  expr.mutable_literal()->mutable_integer_literal();
  EXPECT_EQ(ExpressionToString(expr), "0");

  expr.mutable_expr();
  EXPECT_EQ(ExpressionToString(expr), "0");
}

TEST(ProtoToStringTest, SpecialLiteralTest) {
  using SpecialVal = zetasql_expression_grammar::LiteralExpr_SpecialValue;
  Expression expr;
  expr.mutable_literal()
    ->set_special_literal(SpecialVal::LiteralExpr_SpecialValue_V_NULL);
  EXPECT_EQ(ExpressionToString(expr), "NULL");
}

TEST(ProtoToStringTest, BooleanLiteralTest) {
  Expression expr;
  expr.mutable_literal()
    ->set_bool_literal(true);
  EXPECT_EQ(ExpressionToString(expr), "TRUE");

  expr.mutable_literal()
    ->set_bool_literal(false);
  EXPECT_EQ(ExpressionToString(expr), "FALSE");
}

TEST(ProtoToStringTest, StringLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_string_literal();
  EXPECT_EQ(ExpressionToString(expr), "");

  expr.mutable_literal()
    ->set_string_literal("TeSt");
  EXPECT_EQ(ExpressionToString(expr), "TeSt");

  expr.mutable_literal()
    ->set_string_literal("");
  EXPECT_EQ(ExpressionToString(expr), "");
}

TEST(ProtoToStringTest, BytesLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_bytes_literal();
  EXPECT_EQ(ExpressionToString(expr), "");

  expr.mutable_literal()
    ->set_bytes_literal("TeSt");
  EXPECT_EQ(ExpressionToString(expr), "TeSt");

  expr.mutable_literal()
    ->set_string_literal("\x01\x02");
  EXPECT_EQ(ExpressionToString(expr), "\x01\x02");
}

TEST(ProtoToStringTest, IntegerLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(1);
  EXPECT_EQ(ExpressionToString(expr), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(0);
  EXPECT_EQ(ExpressionToString(expr), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(google::protobuf::kint32max);
EXPECT_EQ(ExpressionToString(expr), "2147483647");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(google::protobuf::kint32min);
  EXPECT_EQ(ExpressionToString(expr), "-2147483648");

  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(1);
  EXPECT_EQ(ExpressionToString(expr), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(0);
  EXPECT_EQ(ExpressionToString(expr), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(google::protobuf::kuint32max);
  EXPECT_EQ(ExpressionToString(expr), "4294967295");

  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(1);
  EXPECT_EQ(ExpressionToString(expr), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(0);
  EXPECT_EQ(ExpressionToString(expr), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(google::protobuf::kint64max);
  EXPECT_EQ(ExpressionToString(expr), "9223372036854775807");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(google::protobuf::kint64min);
  EXPECT_EQ(ExpressionToString(expr), "-9223372036854775808");

  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(1);
  EXPECT_EQ(ExpressionToString(expr), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(0);
  EXPECT_EQ(ExpressionToString(expr), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(google::protobuf::kuint64max);
  EXPECT_EQ(ExpressionToString(expr), "18446744073709551615");
}

TEST(ProtoToStringTest, NumericLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_numeric_literal()
    ->set_value("\xff\xff\xff\xff");
  EXPECT_EQ(ExpressionToString(expr), "\xff\xff\xff\xff");
}

TEST(ProtoToStringTest, CompoundExprTest) {
  using zetasql_expression_grammar::BinaryOperation;
  Expression expr;
  expr.mutable_expr()->mutable_binary_operation()
    ->set_op(BinaryOperation::PLUS);
  expr.mutable_expr()->mutable_binary_operation()
    ->mutable_lhs()->mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(1);
  expr.mutable_expr()->mutable_binary_operation()
    ->mutable_rhs()->mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(1);
  EXPECT_EQ(ExpressionToString(expr), "1 + 1");

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
  EXPECT_EQ(ExpressionToString(expr), "tEsT * 18446744073709551615 - -2147483648");
}

}  // namespace
}  // namespace zetasql_fuzzer