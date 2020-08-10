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

#include "absl/strings/str_cat.h"
#include "gtest/gtest_prod.h"
#include "zetasql/fuzzing/protobuf/zetasql_expression_grammar.pb.h"
#include "zetasql/fuzzing/protobuf/parameter_grammar.pb.h"

namespace zetasql_fuzzer {
namespace internal {

class ProtoExprExtractor {
 public:
  void Extract(const zetasql_expression_grammar::Expression& expr);
  void Extract(const zetasql_expression_grammar::LiteralExpr& literal);
  void Extract(const zetasql_expression_grammar::IntegerLiteral& integer);
  void Extract(const zetasql_expression_grammar::NumericLiteral& numeric);
  void Extract(const zetasql_expression_grammar::CompoundExpr& comp_expr);
  void Extract(const zetasql_expression_grammar::BinaryOperation& binary_operation);
  void Extract(const parameter_grammar::Whitespace& whitespaces);
  inline std::string Data() { return builder_; };

 protected:
  template <typename T>
  inline void ExtractDefault(const T& expr) {
    Append(expr.default_value().content());
  }
  inline void Append(const absl::AlphaNum& value) {
    absl::StrAppend(&builder_, value);
  }

 private:
  std::string builder_;

  inline void Exit(const std::string& error) {
    std::cerr << error << std::endl;
    std::abort();
  }
  inline void Quote(const std::string& content, const std::string& quote);
  inline void ExtractBinaryOperator(
      const zetasql_expression_grammar::BinaryOperation_Operator binary);
  inline void ExtractWhitespaceCharacter(
      const parameter_grammar::Whitespace_Type whitespace);
};

}  // namespace internal
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_ZETASQL_EXPRESSION_EXTRACTOR_H