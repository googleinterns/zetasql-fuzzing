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

#ifndef ZETASQL_FUZZING_SYNTAX_TREE_VISITOR_H
#define ZETASQL_FUZZING_SYNTAX_TREE_VISITOR_H

#include "zetasql/fuzzing/protobuf/parameter_grammar.pb.h"
#include "zetasql/fuzzing/protobuf/zetasql_expression_grammar.pb.h"

// Includes abstract base Visitor class for Protobuf encoded SQL syntax tree.
// See zetasql_expression_grammar.proto and parameter_grammar.proto for 
// syntax tree definition.

namespace zetasql_fuzzer {
namespace internal {

template <typename Result>
class Extractor {
 public:
  virtual ~Extractor() = default;
  virtual const Result& Data() = 0;
};

template <typename Result>
class LiteralExtractor : public Extractor<Result> {
 public:
  virtual ~LiteralExtractor() = default;
  virtual void Extract(const parameter_grammar::Literal& literal) = 0;
  virtual void Extract(const parameter_grammar::IntegerLiteral& integer) = 0;
  virtual void Extract(const parameter_grammar::NumericLiteral& numeric) = 0;
};

template <typename Result>
class ProtoExprExtractor : public Extractor<Result> {
 public:
  virtual ~ProtoExprExtractor() = default;

  virtual void Extract(const parameter_grammar::Value& value) = 0;
  virtual void Extract(const zetasql_expression_grammar::Expression& expr) = 0;
  virtual void Extract(const zetasql_expression_grammar::CompoundExpr& comp_expr) = 0;
  virtual void Extract(const zetasql_expression_grammar::BinaryOperation& binary_operation) = 0;
};

}  // namespace internal
}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_SYNTAX_TREE_VISITOR_H