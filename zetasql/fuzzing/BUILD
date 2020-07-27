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
load("//bazel:fuzzing.bzl", "cc_fuzzer", "cc_proto_fuzzer")

package(
    default_visibility = ["//zetasql/fuzzing:__subpackages__"],
)

cc_library(
    name = "oss_fuzz",
    hdrs = [ "oss_fuzz.h", ]
)

cc_fuzzer(
    name = "simple_evaluator_fuzzer",
    srcs = [ "simple_evaluator_fuzzer.cc", ],
    additional_deps = [ "//zetasql/public:evaluator", ],
)

cc_proto_fuzzer(
    name = "zetasql_expression_fuzzer",
    srcs = [ "zetasql_expression_fuzzer.cc", ],
    additional_deps = [
        "//zetasql/public:evaluator",
        "//zetasql/fuzzing/protobuf:zetasql_expression_cc_proto",
        "//zetasql/fuzzing/protobuf:zetasql_expression_proto_to_string",
    ],
)