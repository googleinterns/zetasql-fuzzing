#
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This directory contains code to perform fuzz testing on ZetaSQL; its logic
# is not part of the real ZetaSQL library.

package(
    default_visibility = ["//zetasql/fuzzing:__subpackages__"],
)

cc_library(
    name = "zetasql_fuzzer_function",
    srcs = [],
    hdrs = [ "function.h" ],
    deps = [
        "//zetasql/public:evaluator_base",
        ":zetasql_fuzzer_argument",
    ]
)

cc_library(
    name = "zetasql_fuzzer_argument",
    srcs = [],
    hdrs = [ "argument.h" ],
    deps = [
        ":zetasql_fuzzer_function",
    ]
)

cc_library(
    name = "zetasql_fuzzer_input",
    srcs = [],
    hdrs = [ "input.h" ],
    deps = [
        ":zetasql_fuzzer_input_visitor",
    ]
)

cc_library(
    name = "zetasql_fuzzer_input_visitor",
    srcs = [],
    hdrs = [ "input_visitor.h" ],
    deps = [
        ":zetasql_fuzzer_input",
        ":zetasql_fuzzer_argument",
    ]
)

cc_library(
    name = "zetasql_fuzzer_runner",
    srcs = [],
    hdrs = [ "runner.h" ],
    deps = [
        ":zetasql_fuzzer_function",
        ":zetasql_fuzzer_input",
        ":zetasql_fuzzer_input_visitor",
    ]
)