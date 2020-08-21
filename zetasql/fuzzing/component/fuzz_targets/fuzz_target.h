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

#include "zetasql/base/logging.h"
#include "zetasql/public/evaluator_base.h"

// FuzzTarget defines an abstraction for any ZetaSQL API to be fuzzed; it 
// encapsulates the logic of setting up call to ZetaSQL API given correct arguments
// During fuzzing, arguments of the API call can be extracted by visiting 
// available zetasql_fuzzer::Argument.
//
// FuzzTarget is a Visitor to zetasql_fuzzer::Argument

namespace zetasql_fuzzer {

class SQLStringArg;
class ParameterValueMapArg;
class ParameterValueListArg;

class FuzzTarget {
 public:
  virtual ~FuzzTarget() = default;
  virtual void Visit(SQLStringArg& arg) { AbortVisit("SQLStringArg&"); }
  virtual void Visit(ParameterValueMapArg& arg) { AbortVisit("ParameterValueMapArg&"); }
  virtual void Visit(ParameterValueListArg& arg) { AbortVisit("ParameterValueListArg&"); }
  virtual void Execute() = 0;

 protected:
  template <typename T>
  static const T& GetOrDefault(
      const std::unique_ptr<T>& ptr) {
    static const T DEFAULT_VALUE;
    return ptr ? *ptr : DEFAULT_VALUE;
  }

 private:
  void AbortVisit(const std::string& type) {
    LOG(FATAL) << "#Visit(" << type
              << ") not implemented. Instantiate this method in the FuzzTarget subclass";
  }
};

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_FUZZ_TARGET_H