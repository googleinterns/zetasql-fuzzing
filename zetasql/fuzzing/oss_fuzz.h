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

// Utilities for OSS-Fuzz Initialization

#if defined(__OSS_FUZZ__) && !defined(ZETASQL_FUZZING_OSS_FUZZ_H_)
#define ZETASQL_FUZZING_OSS_FUZZ_H_

#include <filesystem>

const int OVERWRITE = 1;

namespace zetasql_fuzzer {

bool DoOssFuzzInit() {
  namespace fs = std::filesystem;
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

}

#endif // ZETASQL_FUZZING_OSS_FUZZ_H_