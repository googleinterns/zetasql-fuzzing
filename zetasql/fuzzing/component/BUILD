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
    name = "fuzz_target",
    hdrs = [ 
        "fuzz_targets/fuzz_target.h",
        "arguments/argument.h",
    ],
    deps = [
        "//zetasql/base:logging",
        "//zetasql/base:statusor",
        "//zetasql/public:evaluator_base"
    ]
)

cc_library(
    name = "parameter_value_argument",
    hdrs = [ "arguments/parameter_value_argument.h" ],
    deps = [
        ":fuzz_target",
    ]
)

cc_test(
    name = "argument_test",
    srcs = [ "arguments/argument_test.cc" ],
    deps = [
        ":fuzz_target",
        "//zetasql/base:statusor",
        "@com_google_googletest//:gtest_main",
    ]
)

cc_library(
    name = "prepared_expression_target",
    srcs = [ "fuzz_targets/prepared_expression_target.cc" ],
    hdrs = [ "fuzz_targets/prepared_expression_target.h"],
    deps = [
        ":fuzz_target",
        ":parameter_value_argument",
        "//zetasql/public:evaluator",
    ]
)

cc_library(
    name = "runner",
    srcs = [],
    hdrs = [ "runner.h" ],
    deps = [
        ":fuzz_target",
    ]
)