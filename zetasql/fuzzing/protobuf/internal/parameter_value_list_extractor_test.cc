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

#include "zetasql/fuzzing/protobuf/internal/parameter_value_list_extractor.h"

#include <memory>
#include <string>
#include <tuple>

#include "gtest/gtest.h"

using parameter_grammar::Identifier;
using zetasql_expression_grammar::BinaryOperation;
using zetasql_expression_grammar::CompoundExpr;
using zetasql_expression_grammar::Expression;
using zetasql_fuzzer::internal::ParameterValueListExtractor;

namespace zetasql_fuzzer {
namespace {

class ParameterValueListExtractorTest : public ::testing::TestWithParam<Identifier::Type> {};

TEST_P(ParameterValueListExtractorTest, NonvariableTest) {
  parameter_grammar::Value value;
  value.clear_as_variable();
  value.mutable_literal()->set_bytes_literal("test");

  ParameterValueListExtractor extractor(GetParam());
  extractor.Extract(value);
  EXPECT_EQ(extractor.Data(), ((zetasql::ParameterValueList())));
}

TEST_P(ParameterValueListExtractorTest, VariableTest) {
  parameter_grammar::Value value;
  value.mutable_as_variable()->set_name("test_var");
  value.mutable_as_variable()->set_type(GetParam());
  value.mutable_literal()->set_bytes_literal("test");

  ParameterValueListExtractor extractor(GetParam());
  extractor.Extract(value);
  EXPECT_EQ(extractor.Data(),
            ((zetasql::ParameterValueList{zetasql::Value::Bytes("test")})));
}

TEST_P(ParameterValueListExtractorTest, BinaryExprTest) {
  BinaryOperation binary;
  binary.mutable_lhs()->mutable_value()->mutable_as_variable()->set_name("lhs");
  binary.mutable_lhs()->mutable_value()->mutable_as_variable()->set_type(GetParam());
  binary.mutable_lhs()->mutable_value()->mutable_literal()->set_bytes_literal(
      "TeSt");
  binary.set_op(BinaryOperation::PLUS);
  binary.mutable_rhs()
      ->mutable_value()
      ->mutable_literal()
      ->mutable_integer_literal()
      ->set_int32_literal(1);
  binary.mutable_rhs()->mutable_value()->mutable_as_variable()->set_name("rhs");
  binary.mutable_rhs()->mutable_value()->mutable_as_variable()->set_type(GetParam());

  ParameterValueListExtractor extractor(GetParam());
  extractor.Extract(binary);
  EXPECT_EQ(extractor.Data(),
            ((zetasql::ParameterValueList{zetasql::Value::Bytes("TeSt"),
                                          zetasql::Value::Int32(1)})));
}

TEST_P(ParameterValueListExtractorTest, CompoundExprTest) {
  Expression expr;
  expr.mutable_expr()->mutable_binary_operation()
    ->set_op(BinaryOperation::MULTIPLY);
  expr.mutable_expr()
      ->mutable_binary_operation()
      ->mutable_lhs()
      ->mutable_value()
      ->mutable_literal()
      ->set_string_literal("tEsT");
  expr.mutable_expr()
      ->mutable_binary_operation()
      ->mutable_lhs()
      ->mutable_value()
      ->mutable_as_variable()
      ->set_name("var1");
  expr.mutable_expr()
      ->mutable_binary_operation()
      ->mutable_lhs()
      ->mutable_value()
      ->mutable_as_variable()
      ->set_type(GetParam());

  ParameterValueListExtractor extractor(GetParam());
  auto subexpr = std::make_unique<Expression>();
  subexpr->mutable_expr()->mutable_binary_operation()
    ->set_op(BinaryOperation::MINUS);
  subexpr->mutable_expr()
      ->mutable_binary_operation()
      ->mutable_lhs()
      ->mutable_value()
      ->mutable_literal()
      ->mutable_integer_literal()
      ->set_uint64_literal(google::protobuf::kuint64max);
  subexpr->mutable_expr()
      ->mutable_binary_operation()
      ->mutable_lhs()
      ->mutable_value()
      ->mutable_as_variable()
      ->set_name("var2");
  subexpr->mutable_expr()
      ->mutable_binary_operation()
      ->mutable_lhs()
      ->mutable_value()
      ->mutable_as_variable()
      ->set_type(GetParam());

  subexpr->mutable_expr()
      ->mutable_binary_operation()
      ->mutable_rhs()
      ->mutable_value()
      ->mutable_literal()
      ->mutable_integer_literal()
      ->set_int32_literal(google::protobuf::kint32min);
  subexpr->mutable_expr()
      ->mutable_binary_operation()
      ->mutable_rhs()
      ->mutable_value()
      ->mutable_as_variable()
      ->set_name("var3");
  subexpr->mutable_expr()
      ->mutable_binary_operation()
      ->mutable_rhs()
      ->mutable_value()
      ->mutable_as_variable()
      ->set_type(GetParam());

  expr.mutable_expr()->mutable_binary_operation()
    ->set_allocated_rhs(subexpr.release());

  extractor.Extract(expr);
  zetasql::ParameterValueList result{
      zetasql::Value::StringValue("tEsT"),
      zetasql::Value::Uint64(google::protobuf::kuint64max),
      zetasql::Value::Int32(google::protobuf::kint32min)};
  EXPECT_EQ(extractor.Data(), result);
}

TEST_P(ParameterValueListExtractorTest, IncrementalTest) {
  Expression expr;
  ParameterValueListExtractor extractor(GetParam());

  expr.mutable_value()
      ->mutable_literal()
      ->mutable_integer_literal()
      ->set_int32_literal(1);
  expr.mutable_value()->mutable_as_variable()->set_name("var1");
  expr.mutable_value()->mutable_as_variable()->set_type(GetParam());
  extractor.Extract(expr);

  parameter_grammar::Value num_expr;
  num_expr.mutable_as_variable()->set_name("var2");
  num_expr.mutable_as_variable()->set_type(GetParam());
  num_expr.mutable_literal()->mutable_integer_literal()->set_int32_literal(1234);
  extractor.Extract(num_expr);

  zetasql::ParameterValueList result{
      zetasql::Value::Int32(1),
      zetasql::Value::Int32(1234),
  };
  EXPECT_EQ(extractor.Data(), result);
}

INSTANTIATE_TEST_SUITE_P(IdentifierTypeTest, ParameterValueListExtractorTest,
                         ::testing::Values(Identifier::COLUMN,
                                           Identifier::PARAMETER));

TEST_F(ParameterValueListExtractorTest, TypeValueTest) {
  Expression expr;
  auto binary_expr = expr.mutable_expr()->mutable_binary_operation();
  binary_expr->mutable_rhs()->mutable_value()->mutable_as_variable()->set_type(Identifier::COLUMN);
  binary_expr->mutable_rhs()->mutable_value()->mutable_as_variable()->set_name("col");
  binary_expr->mutable_rhs()->mutable_value()->mutable_literal()->set_bytes_literal("col1");

  binary_expr->mutable_lhs()->mutable_value()->mutable_as_variable()->set_type(Identifier::PARAMETER);
  binary_expr->mutable_lhs()->mutable_value()->mutable_as_variable()->set_name("param");
  binary_expr->mutable_lhs()->mutable_value()->mutable_literal()->set_bytes_literal("param1");

  ParameterValueListExtractor col_extractor(Identifier::COLUMN);
  col_extractor.Extract(expr);
  EXPECT_EQ(col_extractor.Data(),
            ((zetasql::ParameterValueList{zetasql::Value::Bytes("col1")})));

  ParameterValueListExtractor param_extractor(Identifier::PARAMETER);
  param_extractor.Extract(expr);
  EXPECT_EQ(param_extractor.Data(),
            ((zetasql::ParameterValueList{zetasql::Value::Bytes("param1")})));
}

}  // namespace
}  // namespace zetasql_fuzzer