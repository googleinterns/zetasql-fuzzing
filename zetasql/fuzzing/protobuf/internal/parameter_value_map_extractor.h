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

#ifndef ZETASQL_FUZZING_PARAMETER_VALUE_MAP_EXTRACTOR_H
#define ZETASQL_FUZZING_PARAMETER_VALUE_MAP_EXTRACTOR_H

#include "zetasql/fuzzing/protobuf/internal/syntax_tree_visitor.h"
#include "zetasql/public/evaluator_base.h"
#include "zetasql/public/value.h"

namespace zetasql_fuzzer {
namespace internal {

namespace LiteralValueExtractor {
zetasql::Value Extract(const parameter_grammar::Literal& literal);
zetasql::Value Extract(const parameter_grammar::IntegerLiteral& integer);
zetasql::Value Extract(const parameter_grammar::NumericLiteral& numeric);
zetasql::Value Extract(zetasql::TypeKind null_type);
template <typename T>
inline zetasql::Value ExtractDefault(const T& literal) {
  return zetasql::Value::Bytes(literal.default_value().content());
}
}  // namespace LiteralValueExtractor

class ParameterValueMapExtractor : public ProtoExprExtractor<zetasql::ParameterValueMap> {
 public:
  void Extract(const parameter_grammar::Value& value) override;
  void Extract(const zetasql_expression_grammar::Expression& expr) override;
  void Extract(const zetasql_expression_grammar::CompoundExpr& comp_expr) override;
  void Extract(const zetasql_expression_grammar::BinaryOperation& binary_operation) override;
  inline const zetasql::ParameterValueMap& Data() override { return builder_; }

 private:
  zetasql::ParameterValueMap builder_;
};

}  // namespace internal
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_PARAMETER_VALUE_MAP_EXTRACTOR_H