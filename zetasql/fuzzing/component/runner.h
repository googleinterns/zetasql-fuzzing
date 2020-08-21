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

#ifndef ZETASQL_FUZZING_RUNNER_H
#define ZETASQL_FUZZING_RUNNER_H

#include <functional>
#include <memory>

#ifdef __OSS_FUZZ__
#include <filesystem>
#endif  // __OSS_FUZZ__

#include "zetasql/fuzzing/component/arguments/argument.h"
#include "zetasql/fuzzing/component/fuzz_targets/fuzz_target.h"

namespace zetasql_fuzzer {

#ifdef __OSS_FUZZ__
// Configure timezone data dependency for ZetaSQL runtime in OSS-Fuzz 
// docker environment, which doesn't have tzdata dependency installed.
// See also https://github.com/google/oss-fuzz/pull/4010
bool DoOssFuzzInit() {
  namespace fs = std::filesystem;
  static const int OVERWRITE = 1;

  fs::path originDir;
  try {
    originDir = fs::canonical(fs::read_symlink("/proc/self/exe")).parent_path();
  } catch (const std::exception& e) {
    return false;
  }
  fs::path tzdataDir = originDir / "data/zoneinfo/";
  if (setenv("TZDIR", tzdataDir.c_str(), OVERWRITE)) {
    return false;
  }
  return true;
}
#endif  // __OSS_FUZZ__

// Defines the driver function for ZetaSQL fuzzing tests
template <typename InputType, typename TargetType, typename... Functions>
void Run(const InputType& input, Functions... functions) {
#ifdef __OSS_FUZZ__
  static bool Initialized = zetasql_fuzzer::DoOssFuzzInit();
  if (!Initialized) {
    std::abort();
  }
#endif  // __OSS_FUZZ__

  TargetType target;
  for (const std::function<std::unique_ptr<Argument>(const InputType&)>&
           extractor : {functions...}) {
    extractor(input)->Accept(target);
  }
  target.Execute();
}

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_RUNNER_H