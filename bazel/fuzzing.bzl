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

load("@rules_cc//cc:defs.bzl", "cc_binary")

def cc_fuzzer(name, additional_linkopts = [], additional_deps = [], **kwargs):
    """Define a fuzzer test target that is used with OSS-Fuzz project. 
    
    See https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/#fuzz-target

    Args:
        additional_linkopts: linkopts to specify in addition to those for an OSS-Fuzz fuzzer
        additional_deps: deps to specify in addition to those for an OSS-Fuzz fuzzer
    """

    cc_binary(
        name = name,
        linkopts = [ "$(LIB_FUZZING_ENGINE)" ] + additional_linkopts,
        linkstatic = 1,
        testonly = 1,
        deps = [ "//zetasql/fuzzing:oss_fuzz" ] + additional_deps,
        tags = [ "fuzzer" ],
        **kwargs,
    )

def cc_proto_fuzzer(name, additional_linkopts = [], additional_deps = [], **kwargs):
    """Define a fuzzer test target that is used with OSS-Fuzz project and libprotobuf-mutator

    See https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/#fuzz-target

    Args:
        additional_linkopts: linkopts to specify in addition to those for an OSS-Fuzz fuzzer w/ libprotobuf-mutator dependency
        additional_deps: deps to specify in addition to those for an OSS-Fuzz fuzzer w/ libprotobuf-mutator dependency
    """

    cc_fuzzer(
        name,
        additional_linkopts = additional_linkopts,
        additional_deps = [ "@libprotobuf_mutator//:libprotobuf_mutator" ] + additional_deps,
        **kwargs,
    )