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

namespace zetasql_fuzzer {

class SQLStringArg;
class ParameterValueMapArg;

class FuzzTarget {
 public:
  virtual void Visit(SQLStringArg& arg) { AbortVisit("SQLStringArg&"); }
  virtual void Visit(ParameterValueMapArg& arg) { AbortVisit("ParameterValueMapArg&"); }
  virtual void Execute() = 0;

 protected:
  static const zetasql::ParameterValueMap& GetOrDefault(
      const std::unique_ptr<zetasql::ParameterValueMap>& ptr) {
    static const zetasql::ParameterValueMap DEFAULT_VALUE_MAP;
    return ptr ? *ptr : DEFAULT_VALUE_MAP;
  }

 private:
  void AbortVisit(const std::string& type) {
    LOG(FATAL) << "#Visit(" << type
              << ") not implemented. Instantiate this method in the subclass";
  }
};

}  // namespace zetasql_fuzzer

#endif  // ZETASQL_FUZZING_FUZZ_TARGET_H