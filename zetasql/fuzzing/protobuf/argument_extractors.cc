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

#include "zetasql/fuzzing/protobuf/argument_extractors.h"

#include "zetasql/base/logging.h"
#include "zetasql/fuzzing/protobuf/internal/parameter_value_list_extractor.h"
#include "zetasql/fuzzing/protobuf/internal/parameter_value_map_extractor.h"
#include "zetasql/fuzzing/protobuf/internal/zetasql_expression_extractor.h"

namespace zetasql_fuzzer {

namespace {
constexpr parameter_grammar::Identifier::Type GetType(
    zetasql_fuzzer::ParameterValueAs type) {
  switch (type) {
    case ParameterValueAs::COLUMNS:
      return parameter_grammar::Identifier::COLUMN;
    case ParameterValueAs::PARAMETERS:
      return parameter_grammar::Identifier::PARAMETER;
    default:
      LOG(FATAL)
          << "Unhandled ParameterValueAs to Identifier::Type transformation.";
  }
}
}  // namespace

std::unique_ptr<Argument> GetProtoExpr(
    const zetasql_expression_grammar::Expression& expression) {
  zetasql_fuzzer::internal::SQLExprExtractor extractor;
  extractor.Extract(expression);
  return std::make_unique<SQLStringArg>(extractor.Data());
}

template <ParameterValueAs Intent>
std::unique_ptr<Argument> GetParam(
    const zetasql_expression_grammar::Expression& expression) {
  zetasql_fuzzer::internal::ParameterValueMapExtractor extractor(GetType(Intent));
  extractor.Extract(expression);
  return std::make_unique<ParameterValueMapArg>(extractor.Data(), Intent);
}

template std::unique_ptr<Argument> GetParam<ParameterValueAs::COLUMNS>(
    const zetasql_expression_grammar::Expression& expression);
template std::unique_ptr<Argument> GetParam<ParameterValueAs::PARAMETERS>(
    const zetasql_expression_grammar::Expression& expression);

template <ParameterValueAs Intent>
std::unique_ptr<Argument> GetPositionalParam(
    const zetasql_expression_grammar::Expression& expression) {
  zetasql_fuzzer::internal::ParameterValueListExtractor extractor(GetType(Intent));
  extractor.Extract(expression);
  return std::make_unique<ParameterValueListArg>(extractor.Data(), Intent);
}

template std::unique_ptr<Argument> GetPositionalParam<ParameterValueAs::COLUMNS>(
    const zetasql_expression_grammar::Expression& expression);
template std::unique_ptr<Argument> GetPositionalParam<ParameterValueAs::PARAMETERS>(
    const zetasql_expression_grammar::Expression& expression);
}  // namespace zetasql_fuzzer