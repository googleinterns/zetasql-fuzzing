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

#include "zetasql/fuzzing/protobuf/internal/literal_value_extractor.h"

using parameter_grammar::Identifier;
using parameter_grammar::IntegerLiteral;
using parameter_grammar::Literal;
using parameter_grammar::NumericLiteral;
using parameter_grammar::Whitespace;

namespace zetasql_fuzzer {
namespace internal {
namespace LiteralValueExtractor {

zetasql::Value Extract(const parameter_grammar::Literal& literal) {
  switch (literal.literal_oneof_case()) {
    case Literal::kBoolLiteral:
      return zetasql::Value::Bool(literal.bool_literal());
    case Literal::kNullLiteral:
      return Extract(literal.null_literal());
    case Literal::kBytesLiteral:
      return zetasql::Value::Bytes(literal.bytes_literal());
    case Literal::kStringLiteral:
      return zetasql::Value::StringValue(literal.string_literal());
    case Literal::kIntegerLiteral:
      return Extract(literal.integer_literal());
    case Literal::kNumericLiteral:
      return Extract(literal.numeric_literal());
    default:
      return ExtractDefault(literal);
  }
}

zetasql::Value Extract(const parameter_grammar::IntegerLiteral& integer) {
  switch (integer.integer_oneof_case()) {
    case IntegerLiteral::kInt32Literal:
      return zetasql::Value::Int32(integer.int32_literal());
    case IntegerLiteral::kInt64Literal:
      return zetasql::Value::Int64(integer.int64_literal());
    case IntegerLiteral::kUint32Literal:
      return zetasql::Value::Uint32(integer.uint32_literal());
    case IntegerLiteral::kUint64Literal:
      return zetasql::Value::Uint64(integer.uint64_literal());
    default:
      return ExtractDefault(integer);
  }
}

zetasql::Value Extract(const parameter_grammar::NumericLiteral& numeric) {
  auto value(zetasql::NumericValue::FromString(numeric.value()));
  if (value) {
    return zetasql::Value::Numeric(value.value());
  }
  return zetasql::Value::Numeric((zetasql::NumericValue()));
}

zetasql::Value Extract(zetasql::TypeKind null_type) {
  switch (null_type) {
    case zetasql::TYPE_INT32:
    case zetasql::TYPE_INT64:
    case zetasql::TYPE_UINT32:
    case zetasql::TYPE_UINT64:
    case zetasql::TYPE_BOOL:
    case zetasql::TYPE_FLOAT:
    case zetasql::TYPE_DOUBLE:
    case zetasql::TYPE_STRING:
    case zetasql::TYPE_BYTES:
    case zetasql::TYPE_TIMESTAMP:
    case zetasql::TYPE_DATE:
    case zetasql::TYPE_TIME:
    case zetasql::TYPE_DATETIME:
    case zetasql::TYPE_GEOGRAPHY:
    case zetasql::TYPE_NUMERIC:
    case zetasql::TYPE_BIGNUMERIC:
      return zetasql::Value::Null(
          zetasql::types::TypeFromSimpleTypeKind(null_type));
    // Treat all other types as invalid type
    default:
      return zetasql::Value::Invalid();
  }
}

}  // namespace LiteralValueExtractor
}  // namespace internal
}  // namespace zetasql_fuzzer