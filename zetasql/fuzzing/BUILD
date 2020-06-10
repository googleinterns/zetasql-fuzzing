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
    default_visibility = ["//:__subpackages__"],
)

cc_binary(
    name = "simple_evaluator_fuzzer",
    srcs = [
        "simple_evaluator_fuzzer.cc",
    ],
    linkopts = [ "$(LIB_FUZZING_ENGINE)" ],
    linkstatic = 1,
    testonly = 1,
    deps = [
        "//zetasql/public:evaluator",
    ],
)
