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

#include <memory>

#include "libprotobuf_mutator/src/libfuzzer/libfuzzer_macro.h"
#include "zetasql/fuzzing/protobuf/zetasql_expression_grammar.pb.h"
#include "zetasql/fuzzing/component/runner.h"
#include "zetasql/fuzzing/component/fuzz_targets/prepared_expression_target.h"
#include "zetasql/fuzzing/protobuf/argument_extractors.h"

using zetasql_expression_grammar::Expression;
using zetasql_fuzzer::PreparedExpressionTarget;
using zetasql_fuzzer::GetProtoExpr;

// This can be turned in to a macro easily
// #define ZETASQL_PROTO_FUZZER(InputType, TargetType, ...) \
//   DEFINE_PROTO_FUZZER(const InputType& input) { \
//     zetasql_fuzzer::Run<InputType, TargetType>(input __VA_OPT__(,) __VA_ARGS__); \
//   }
DEFINE_PROTO_FUZZER(const Expression& expression) {
  zetasql_fuzzer::Run<Expression, PreparedExpressionTarget>(expression,
                                                            GetProtoExpr);
}