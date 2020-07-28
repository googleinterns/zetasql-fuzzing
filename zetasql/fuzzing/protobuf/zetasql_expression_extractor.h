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

class ProtoExprExtractor {
 public:
  void Extract(const zetasql_expression_grammar::Expression& expr);
  void Extract(const zetasql_expression_grammar::LiteralExpr& literal);
  void Extract(const zetasql_expression_grammar::IntegerLiteral& integer);
  void Extract(const zetasql_expression_grammar::NumericLiteral& numeric);
  void Extract(const zetasql_expression_grammar::CompoundExpr& comp_expr);
  void Extract(const zetasql_expression_grammar::BinaryOperation& binary_operation);
  void Extract(const parameter_grammar::Whitespace& whitespace);
  std::string Release();

 private:
  std::string builder;
  FRIEND_TEST(ProtoExprExtractorTest, ExtractorReleaseTest);

  inline void Exit(const std::string& error) {
    std::cerr << error << std::endl;
    std::abort();
  }
  inline void TryCatch(const std::function<void()>& callback) {
    try {
      callback();
    } catch (const std::exception& e) {
      Exit(e.what());
    }
  }
  inline void Append(const absl::AlphaNum& value) {
    absl::StrAppend(&builder, value);
  }
  inline void Quote(const std::string& content, const std::string& quote);
  template <typename T>
  inline void ExtractDefault(const T& expr);
};

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_ZETASQL_EXPRESSION_EXTRACTOR_H