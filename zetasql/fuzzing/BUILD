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
    default_visibility = ["//:__subpackages__"],
)

cc_binary(
    name = "simple_evaluator_fuzzer",
    srcs = [
        "simple_evaluator_fuzzer.cc",
        "oss_fuzz.h",
    ],
    linkopts = [ "$(LIB_FUZZING_ENGINE)" ],
    linkstatic = 1,
    testonly = 1,
    deps = [
        "//zetasql/public:evaluator",
    ],
)

cc_binary(
    name = "zetasql_expression_fuzzer",
    srcs = [
        "zetasql_expression_fuzzer.cc",
        "oss_fuzz.h",
    ],
    linkopts = [ "$(LIB_FUZZING_ENGINE)" ],
    linkstatic = 1,
    testonly = 1,
    deps = [
        "//zetasql/public:evaluator",
        ":zetasql_expression_cc_proto",
        ":zetasql_expression_proto_to_string",
        "@libprotobuf_mutator//:libprotobuf_mutator",
    ],
)

cc_library(
    name = "zetasql_expression_proto_to_string",
    srcs = [
        "zetasql_expression_proto_to_string.cc",
    ],
    hdrs = [ "zetasql_expression_proto_to_string.h" ],
    deps = [
        ":zetasql_expression_cc_proto",
        ":common",
    ]
)

cc_test(
    name = "zetasql_expression_proto_to_string_test",
    srcs = ["zetasql_expression_proto_to_string_test.cc"],
    deps = [
        ":zetasql_expression_cc_proto",
        ":zetasql_expression_proto_to_string",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "common",
    hdrs = [ "common.h" ],
)

cc_proto_library(
    name = "zetasql_expression_cc_proto",
    deps = [ ":zetasql_expression_proto", ],
)

proto_library(
    name = "zetasql_expression_proto",
    srcs = [ "zetasql_expression_grammar.proto", ]
)