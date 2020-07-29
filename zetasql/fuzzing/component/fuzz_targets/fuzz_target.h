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

#ifndef ZETASQL_FUZZING_FUZZ_TARGET_H
#define ZETASQL_FUZZING_FUZZ_TARGET_H

#include <iostream>
#include <string>

namespace zetasql_fuzzer {

class SQLStringArg;

class FuzzTarget {
 public:
  // virtual void Visit(PositionalArg<zetasql::ParameterValueMap>& arg);
  virtual void Visit(SQLStringArg& arg) { AbortVisit("SQLStringArg&"); }
  virtual void Execute() = 0;

 private:
  virtual void AbortVisit(const std::string& type) {
    std::cerr << "#Visit(" << type
              << ") not implemented. Instantiate this method in the subclass"
              << std::endl;
    std::abort();
  }
};

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_FUZZ_TARGET_H