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

#include "zetasql/fuzzing/protobuf/internal/parameter_value_map_extractor.h"

#include <memory>
#include <string>
#include <tuple>

#include "gtest/gtest.h"

using zetasql_expression_grammar::BinaryOperation;
using zetasql_expression_grammar::CompoundExpr;
using zetasql_expression_grammar::Expression;
using zetasql_fuzzer::internal::ParameterValueMapExtractor;

namespace zetasql_fuzzer {
namespace {
  
TEST(ParameterValueMapTest, NonvariableTest) {
  parameter_grammar::Value value;
  value.clear_as_variable();
  value.mutable_literal()->set_bytes_literal("test");

  ParameterValueMapExtractor extractor;
  extractor.Extract(value);
  EXPECT_EQ(extractor.Data(), ((zetasql::ParameterValueMap())));
}

TEST(ParameterValueMapTest, VariableTest) {
  parameter_grammar::Value value;
  value.mutable_as_variable()->set_name("test_var");
  value.mutable_literal()->set_bytes_literal("test");

  ParameterValueMapExtractor extractor;
  extractor.Extract(value);
  EXPECT_EQ(extractor.Data(),
            ((zetasql::ParameterValueMap{
                {"test_var", zetasql::Value::Bytes("test")}})));
}

TEST(ParameterValueMapTest, BinaryExprTest) {
  BinaryOperation binary;
  binary.mutable_lhs()->mutable_value()->mutable_as_variable()->set_name("lhs");
  binary.mutable_lhs()->mutable_value()->mutable_literal()->set_bytes_literal(
      "TeSt");
  binary.set_op(BinaryOperation::PLUS);
  binary.mutable_rhs()
      ->mutable_value()
      ->mutable_literal()
      ->mutable_integer_literal()
      ->set_int32_literal(1);
  binary.mutable_rhs()->mutable_value()->mutable_as_variable()->set_name("rhs");

  ParameterValueMapExtractor extractor;
  extractor.Extract(binary);
  EXPECT_EQ(extractor.Data(),
            ((zetasql::ParameterValueMap{{"lhs", zetasql::Value::Bytes("TeSt")},
                                         {"rhs", zetasql::Value::Int32(1)}})));
}

TEST(ParameterValueMapTest, CompoundExprTest) {
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

  expr.mutable_expr()->mutable_binary_operation()
    ->set_allocated_rhs(subexpr.release()); 
  ParameterValueMapExtractor extractor;
  extractor.Extract(expr);
  zetasql::ParameterValueMap result{
      {"var1", zetasql::Value::StringValue("tEsT")},
      {"var2", zetasql::Value::Uint64(google::protobuf::kuint64max)},
      {"var3", zetasql::Value::Int32(google::protobuf::kint32min)}};
  EXPECT_EQ(extractor.Data(), result);
}

TEST(ParameterValueMapTest, IncrementalTest) {
  Expression expr;
  ParameterValueMapExtractor extractor;

  expr.mutable_value()
      ->mutable_literal()
      ->mutable_integer_literal()
      ->set_int32_literal(1);
  expr.mutable_value()->mutable_as_variable()->set_name("var1");
  extractor.Extract(expr);

  parameter_grammar::Value num_expr;
  num_expr.mutable_as_variable()->set_name("var2");
  num_expr.mutable_literal()->mutable_integer_literal()->set_int32_literal(1234);
  extractor.Extract(num_expr);

  zetasql::ParameterValueMap result{
      {"var1", zetasql::Value::Int32(1)},
      {"var2", zetasql::Value::Int32(1234)},
  };
  EXPECT_EQ(extractor.Data(), result);
}

}  // namespace
}  // namespace zetasql_fuzzer