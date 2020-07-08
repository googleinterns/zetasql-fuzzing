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

#include <string>

#include "zetasql/fuzzing/zetasql_expression_grammar.pb.h"
#include "zetasql/fuzzing/zetasql_expression_proto_to_string.h"
#include "gtest/gtest.h"

using namespace zetasql_expression_grammar;

namespace zetasql_fuzzer {

TEST(ProtoToStringTest, UninitializedOneOfExprTest) {
  Expression expr;
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");

  expr.mutable_literal();
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");

  expr.mutable_literal()->mutable_integer_literal();
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");

  expr.mutable_expr();
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");
}

TEST(ProtoToStringTest, SpecialLiteralTest) {
  Expression expr;
  expr.mutable_literal()
    ->set_special_literal(LiteralExpr_SpecialValue_V_NULL);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "NULL");
}

TEST(ProtoToStringTest, BooleanLiteralTest) {
  Expression expr;
  expr.mutable_literal()
    ->set_bool_literal(true);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "TRUE");

  expr.mutable_literal()
    ->set_bool_literal(false);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "FALSE");
}

TEST(ProtoToStringTest, StringLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_string_literal();
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "");

  expr.mutable_literal()
    ->set_string_literal("TeSt");
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "TeSt");

  expr.mutable_literal()
    ->set_string_literal("");
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "");
}

TEST(ProtoToStringTest, BytesLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_bytes_literal();
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "");

  expr.mutable_literal()
    ->set_bytes_literal("TeSt");
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "TeSt");

  expr.mutable_literal()
    ->set_string_literal("\x01\x02");
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "\x01\x02");
}

TEST(ProtoToStringTest, IntegerLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(1);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(0);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(google::protobuf::kint32max);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "2147483647");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(google::protobuf::kint32min);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "-2147483648");

  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(1);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(0);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(google::protobuf::kuint32max);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "4294967295");

  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(1);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(0);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(google::protobuf::kint64max);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "9223372036854775807");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_int64_literal(google::protobuf::kint64min);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "-9223372036854775808");

  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(1);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "1");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(0);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "0");
  expr.mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(google::protobuf::kuint64max);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "18446744073709551615");
}

TEST(ProtoToStringTest, NumericLiteralTest) {
  Expression expr;
  expr.mutable_literal()->mutable_numeric_literal()
    ->set_value("\xff\xff\xff\xff");
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "\xff\xff\xff\xff");
}

TEST(ProtoToStringTest, CompoundExprTest) {
  Expression expr;
  expr.mutable_expr()->mutable_additive()
    ->set_operator_(AdditiveOperation::PLUS);
  expr.mutable_expr()->mutable_additive()
    ->mutable_lhs()->mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(1);
  expr.mutable_expr()->mutable_additive()
    ->mutable_rhs()->mutable_literal()->mutable_integer_literal()
    ->set_uint32_literal(1);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "1 + 1");

  expr.mutable_expr()->mutable_multiplicative()
    ->set_operator_(MultiplicativeOperation::MULTIPLY);
  expr.mutable_expr()->mutable_multiplicative()
    ->mutable_lhs()->mutable_literal()->set_string_literal("tEsT");

  Expression* subexpr = new Expression;
  subexpr->mutable_expr()->mutable_additive()
    ->set_operator_(AdditiveOperation::MINUS);
  subexpr->mutable_expr()->mutable_additive()
    ->mutable_lhs()->mutable_literal()->mutable_integer_literal()
    ->set_uint64_literal(google::protobuf::kuint64max);
  subexpr->mutable_expr()->mutable_additive()
    ->mutable_rhs()->mutable_literal()->mutable_integer_literal()
    ->set_int32_literal(google::protobuf::kint32min);

  expr.mutable_expr()->mutable_multiplicative()
    ->set_allocated_rhs(subexpr);
  EXPECT_STREQ(ExpressionToString(expr).c_str(), "tEsT * 18446744073709551615 - -2147483648");
}

} // zetasql_fuzzer