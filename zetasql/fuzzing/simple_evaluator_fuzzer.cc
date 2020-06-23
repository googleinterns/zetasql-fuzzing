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

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "zetasql/public/evaluator.h"

#ifdef __OSS_FUZZ__
#define OVERWRITE 1

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
#endif

// Fuzz target interface implementaion. This function takes of length *Size* 
// an array of randomly generated input of uint8_t, and tries to interpret it
// as a SQL expression.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  #ifdef __OSS_FUZZ__
    static bool Initialized = DoOssFuzzInit();
    if (!Initialized) { std::abort(); }
  #endif

  const std::string sqlExp(reinterpret_cast<const char*>(Data), Size);
  zetasql::PreparedExpression expression(sqlExp);
  return 0;
}