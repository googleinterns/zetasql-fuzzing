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

#include <iostream>

#include "libprotobuf_mutator/src/libfuzzer/libfuzzer_macro.h"
#include "zetasql/public/evaluator.h"
#include "zetasql/fuzzing/oss_fuzz.h"
#include "zetasql/fuzzing/zetasql_expression_grammar.pb.h"
#include "zetasql/fuzzing/zetasql_expression_proto_to_string.h"

using namespace zetasql_expression_grammar;

DEFINE_PROTO_FUZZER(const Expression& expression) {
    #ifdef __OSS_FUZZ__
      static bool Initialized = zetasql_fuzzer::DoOssFuzzInit();
      if (!Initialized) {
        std::abort();
      }
    #endif

    std::string sqlExp = zetasql_fuzzer::ExpressionToString(expression);
    zetasql::PreparedExpression zetasqlExpression(sqlExp);
    zetasqlExpression.Execute(); // Value ignored
}