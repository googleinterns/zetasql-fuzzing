#
# Copyright 2019 ZetaSQL Authors
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

""" Step 1 to load ZetaSQL dependencies. """

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# rules_foreign_cc and grpc (transitively) both require a "bazel_version" repo
# but depend on them being something different. So we have to override them both
# by defining the repo first.
load("@com_google_zetasql//bazel:zetasql_bazel_version.bzl", "zetasql_bazel_version")

def zetasql_deps_step_1():
    zetasql_bazel_version()

    if not native.existing_rule("rules_foreign_cc"):
        http_archive(
            name = "rules_foreign_cc",
            strip_prefix = "rules_foreign_cc-ed3db61a55c13da311d875460938c42ee8bbc2a5",
            urls = [
                "https://github.com/bazelbuild/rules_foreign_cc/archive/ed3db61a55c13da311d875460938c42ee8bbc2a5.tar.gz",
            ],
            sha256 = "219bc7280bbb9305938d76067c816954ad2cc0629063412e8b765e9bc6972304",
        )

    if not native.existing_rule("bazel_skylib"):
        http_archive(
            name = "bazel_skylib",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.0.2/bazel-skylib-1.0.2.tar.gz",
                "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.2/bazel-skylib-1.0.2.tar.gz",
            ],
            sha256 = "97e70364e9249702246c0e9444bccdc4b847bed1eb03c5a3ece4f83dfe6abc44",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.12.3.tar.gz"],
            sha256 = "71030a04aedf9f612d2991c1c552317038c3c5a2b578ac4745267a45e7037c29",
            strip_prefix = "protobuf-3.12.3",
        )
