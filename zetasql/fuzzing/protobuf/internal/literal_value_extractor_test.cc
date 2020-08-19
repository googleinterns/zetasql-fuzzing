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

#include "zetasql/fuzzing/protobuf/internal/literal_value_extractor.h"

#include <memory>
#include <string>
#include <tuple>

#include "gtest/gtest.h"
#include "zetasql/public/numeric_value.h"

using parameter_grammar::IntegerLiteral;
using parameter_grammar::Literal;
using parameter_grammar::NumericLiteral;
using parameter_grammar::Whitespace;

namespace zetasql_fuzzer {
namespace {
  
using ExtractLiteralCallback = std::function<zetasql::Value(void)>;
class LiteralValueExtractorTest
    : public ::testing::TestWithParam<
          std::tuple<ExtractLiteralCallback, zetasql::Value>> {};

TEST_P(LiteralValueExtractorTest, ExtractTest) {
  EXPECT_EQ(std::get<0>(GetParam())(), std::get<1>(GetParam()));
}

ExtractLiteralCallback ExtractableNullLiteral(zetasql::TypeKind kind) {
  return [kind]() {
    Literal literal;
    literal.set_null_literal(kind);
    return internal::LiteralValueExtractor::Extract(literal);
  };
}

INSTANTIATE_TEST_SUITE_P(
    NullLiteralValueTest, LiteralValueExtractorTest,
    ::testing::Values(
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_INT32), zetasql::Value::NullInt32()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_INT64), zetasql::Value::NullInt64()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_UINT32), zetasql::Value::NullUint32()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_UINT64), zetasql::Value::NullUint64()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_BOOL), zetasql::Value::NullBool()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_FLOAT), zetasql::Value::NullFloat()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_DOUBLE), zetasql::Value::NullDouble()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_STRING), zetasql::Value::NullString()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_BYTES), zetasql::Value::NullBytes()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_DATE), zetasql::Value::NullDate()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_TIMESTAMP), zetasql::Value::NullTimestamp()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_TIME), zetasql::Value::NullTime()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_DATETIME), zetasql::Value::NullDatetime()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_GEOGRAPHY), zetasql::Value::NullGeography()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_NUMERIC), zetasql::Value::NullNumeric()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_BIGNUMERIC), zetasql::Value::NullBigNumeric()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::__TypeKind__switch_must_have_a_default__), zetasql::Value()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_UNKNOWN), zetasql::Value()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_ENUM), zetasql::Value()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_ARRAY), zetasql::Value()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_STRUCT), zetasql::Value()),
      std::make_tuple(ExtractableNullLiteral(zetasql::TypeKind::TYPE_PROTO), zetasql::Value())
    ));

template <typename LiteralType>
ExtractLiteralCallback ExtractableEmptyLiteral() {
  return []() {
    return internal::LiteralValueExtractor::Extract((LiteralType()));
  };
}

INSTANTIATE_TEST_SUITE_P(
    EmptyLiteralTest, LiteralValueExtractorTest,
    ::testing::Combine(
        ::testing::Values(ExtractableEmptyLiteral<Literal>(),
                          ExtractableEmptyLiteral<IntegerLiteral>()),
        ::testing::Values(zetasql::Value::Bytes(""))));

template <typename LiteralType>
ExtractLiteralCallback ExtractableDefaultValue(const std::string& value) {
  return [value]() {
    LiteralType literal;
    literal.mutable_default_value()->set_content(value);
    return internal::LiteralValueExtractor::Extract(literal);
  };
}

INSTANTIATE_TEST_SUITE_P(
    DefaultOneOfValueTest, LiteralValueExtractorTest,
    ::testing::Values(
        std::make_tuple(ExtractableDefaultValue<Literal>("default_lit"),
                        zetasql::Value::Bytes("default_lit")),
        std::make_tuple(ExtractableDefaultValue<IntegerLiteral>("default_int"),
                        zetasql::Value::Bytes("default_int"))));

ExtractLiteralCallback ExtractableStringLiteral(
    const std::string& value) {
  return [value]() {
    Literal expr;
    expr.set_string_literal(value);
    return internal::LiteralValueExtractor::Extract(expr);
  };
}

INSTANTIATE_TEST_SUITE_P(
    StringLiteralTest, LiteralValueExtractorTest,
    ::testing::Values(std::make_tuple(ExtractableStringLiteral(""),
                                      zetasql::Value::StringValue("")),
                      std::make_tuple(ExtractableStringLiteral("tEsT"),
                                      zetasql::Value::StringValue("tEsT"))));

ExtractLiteralCallback ExtractableBytesLiteral(
    const std::string& value) {
  return [value]() {
    Literal expr;
    expr.set_bytes_literal(value);
    return internal::LiteralValueExtractor::Extract(expr);
  };
}

INSTANTIATE_TEST_SUITE_P(
    BytesLiteralTest, LiteralValueExtractorTest,
    ::testing::Values(
        std::make_tuple(ExtractableBytesLiteral(""), zetasql::Value::Bytes("")),
        std::make_tuple(ExtractableBytesLiteral("TeSt"), zetasql::Value::Bytes("TeSt")),
        std::make_tuple(ExtractableBytesLiteral("\x01\x02"), zetasql::Value::Bytes("\x01\x02"))));

template <IntegerLiteral::IntegerOneofCase IntegerType, typename T>
ExtractLiteralCallback ExtractableIntegerLiteral(T value) {
  return [value]() {
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
    return internal::LiteralValueExtractor::Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
  IntegerLiteralTest, LiteralValueExtractorTest,
  ::testing::Values(
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(1), zetasql::Value::Int32(1)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(0), zetasql::Value::Int32(0)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(google::protobuf::kint32max), zetasql::Value::Int32(2147483647)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt32Literal>(google::protobuf::kint32min), zetasql::Value::Int32(-2147483648)),

    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint32Literal>(1), zetasql::Value::Uint32(1)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint32Literal>(0), zetasql::Value::Uint32(0)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint32Literal>(google::protobuf::kuint32max), zetasql::Value::Uint32(4294967295)),

    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(1), zetasql::Value::Int64(1)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(0), zetasql::Value::Int64(0)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(google::protobuf::kint64max), zetasql::Value::Int64(9223372036854775807)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kInt64Literal>(google::protobuf::kint64min), zetasql::Value::Int64(-9223372036854775808)),

    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint64Literal>(1), zetasql::Value::Uint64(1)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint64Literal>(0), zetasql::Value::Uint64(0)),
    std::make_tuple(ExtractableIntegerLiteral<IntegerLiteral::kUint64Literal>(google::protobuf::kuint64max), zetasql::Value::Uint64(18446744073709551615))
  )
);

ExtractLiteralCallback ExtractableNumeric(const std::string& value) {
  return [value]() {
    NumericLiteral expression;
    expression.set_value(value);
    return internal::LiteralValueExtractor::Extract(expression);
  };
}

INSTANTIATE_TEST_SUITE_P(
    NumericLiteralTest, LiteralValueExtractorTest,
    ::testing::Values(
      std::make_tuple(ExtractableNumeric("12345"), zetasql::Value::Numeric(zetasql::NumericValue(12345))),
      std::make_tuple(ExtractableNumeric("123.45"), zetasql::Value::Numeric(zetasql::NumericValue::FromString("123.45").ValueOrDie())),
      std::make_tuple(ExtractableNumeric("1234sdf"), zetasql::Value::Numeric(zetasql::NumericValue(0)))
    ));

}  // namespace
}  // namespace zetasql_fuzzer