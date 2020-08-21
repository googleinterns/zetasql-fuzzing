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

load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//zetasql/fuzzing/protobuf:__subpackages__"],
)

cc_library(
    name = "syntax_tree_visitor",
    hdrs = [ "syntax_tree_visitor.h", ],
    deps = [
        "//zetasql/fuzzing/protobuf:parameter_cc_proto",
        "//zetasql/fuzzing/protobuf:zetasql_expression_cc_proto",
    ]
)

cc_library(
    name = "zetasql_expression_extractor",
    srcs = [ "zetasql_expression_extractor.cc", ],
    hdrs = [ "zetasql_expression_extractor.h", ],
    deps = [
        ":syntax_tree_visitor",
        "//zetasql/base:logging",
        "@com_google_absl//absl/strings",
    ]
)

cc_test(
    name = "zetasql_expression_extractor_test",
    srcs = [ "zetasql_expression_extractor_test.cc", ],
    deps = [
        ":zetasql_expression_extractor",
        "//zetasql/public:type",
        "@com_google_googletest//:gtest_main",
    ]
)

cc_library(
    name = "literal_value_extractor",
    srcs = [ "literal_value_extractor.cc" ],
    hdrs = [ "literal_value_extractor.h" ],
    deps = [
        "//zetasql/public:value",
        "//zetasql/fuzzing/protobuf:parameter_cc_proto",
    ]
)

cc_test(
    name = "literal_value_extractor_test",
    srcs = [ "literal_value_extractor_test.cc" ],
    deps = [
        ":literal_value_extractor",
        "//zetasql/public:numeric_value",
        "@com_google_googletest//:gtest_main",
    ]
)

cc_library(
    name = "parameter_value_map_extractor",
    srcs = [ "parameter_value_map_extractor.cc" ],
    hdrs = [ "parameter_value_map_extractor.h" ],
    deps = [
        ":syntax_tree_visitor",
        ":literal_value_extractor",
        "//zetasql/public:evaluator_base"
    ]
)

cc_test(
    name = "parameter_value_map_extractor_test",
    srcs = [ "parameter_value_map_extractor_test.cc" ],
    deps = [
        ":parameter_value_map_extractor",
        "@com_google_googletest//:gtest_main",
    ]
)

cc_library(
    name = "parameter_value_list_extractor",
    srcs = [ "parameter_value_list_extractor.cc" ],
    hdrs = [ "parameter_value_list_extractor.h" ],
    deps = [
        ":syntax_tree_visitor",
        ":literal_value_extractor",
        "//zetasql/public:evaluator_base"
    ]
)

cc_test(
    name = "parameter_value_list_extractor_test",
    srcs = [ "parameter_value_list_extractor_test.cc" ],
    deps = [
        ":parameter_value_list_extractor",
        "@com_google_googletest//:gtest_main",
    ]
)