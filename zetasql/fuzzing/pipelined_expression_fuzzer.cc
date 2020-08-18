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

#include "zetasql/fuzzing/component/fuzz_targets/prepared_expression_target.h"
#include "zetasql/fuzzing/fuzzer_macro.h"
#include "zetasql/fuzzing/protobuf/argument_extractors.h"
#include "zetasql/fuzzing/protobuf/zetasql_expression_grammar.pb.h"

using zetasql_expression_grammar::Expression;
using zetasql_fuzzer::GetProtoExpr;
using zetasql_fuzzer::PreparedExpressionTarget;
using As = zetasql_fuzzer::ParameterValueMapArg::As;

ZETASQL_PROTO_FUZZER(Expression, PreparedExpressionTarget, GetProtoExpr,
                     zetasql_fuzzer::GetParam<As::COLUMNS>);
// , GetColumns);