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

#ifndef ZETASQL_FUZZING_ZETASQL_EXPRESSION_EXTRACTOR_H
#define ZETASQL_FUZZING_ZETASQL_EXPRESSION_EXTRACTOR_H

#include <string>

#include "absl/strings/str_cat.h"
#include "zetasql/fuzzing/protobuf/internal/syntax_tree_visitor.h"

namespace zetasql_fuzzer {
namespace internal {

// Defines a Protobuf encoded SQL syntax tree visitor that converts
// the syntax tree to a SQL expression statement string
class SQLExprExtractor : public ProtoExprExtractor<std::string>,
                         public LiteralExtractor<std::string> {
 public:
  void Extract(const parameter_grammar::Literal& literal) override;
  void Extract(const parameter_grammar::IntegerLiteral& integer) override;
  void Extract(const parameter_grammar::NumericLiteral& numeric) override;

  void Extract(const parameter_grammar::Identifier& id);
  void Extract(const parameter_grammar::Whitespace& whitespaces);

  void Extract(const parameter_grammar::Value& value) override;

  void Extract(const zetasql_expression_grammar::Expression& expr) override;
  void Extract(const zetasql_expression_grammar::CompoundExpr& comp_expr) override;
  void Extract(const zetasql_expression_grammar::BinaryOperation& binary_operation) override;
  inline const std::string& Data() override { return builder_; };

 protected:
  // Extract default content of an unset Protobuf one_of struct
  template <typename T>
  inline void ExtractDefault(const T& expr) {
    Append(expr.default_value().content());
  }
  inline void Append(const absl::AlphaNum& value) {
    absl::StrAppend(&builder_, value);
  }

 private:
  std::string builder_;

  inline void Quote(const std::string& content, const std::string& quote);
  inline void ExtractBinaryOperator(
      const zetasql_expression_grammar::BinaryOperation_Operator binary);
  inline void ExtractWhitespaceCharacter(
      const parameter_grammar::Whitespace_Type whitespace);
};

}  // namespace internal
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_ZETASQL_EXPRESSION_EXTRACTOR_H