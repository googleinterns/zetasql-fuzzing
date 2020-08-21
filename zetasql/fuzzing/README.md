## Documentation of ZetaSQL Fuzzing Library (FAIR)

### Code Deprecation and Notes

As part of the experimental code, `zetasql_expression_fuzzer.cc` has been replaced by `pipelined_expression_fuzzer.cc` but with FAIR library integration. `zetasql_expression_fuzzer.cc` and its dependencies existed only for convenient bug reproduction. Future developer should model after `pipelined_expression_fuzzer.cc` for correct use of FAIR library.

The current Bazel build dependency isn't exactly at its finest, and combining with `fuzzer_macro.h`, every fuzzer will be compiled with `libprotobuf-mutator` dependency whether it's defined as a `cc_proto_fuzzer` or `cc_fuzzer`. Effort to separate the dependency is welcomed.

### FAIR Library

#### Before you start

This documentation assumes that readers know how to correctly configure ZetaSQL project and would like to know how to contribute to ZetaSQL fuzzing specifically. Developers who don't have background of Fuzzing Tests or OSS-Fuzz are suggested to take quick tutorials [here](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md) and [here](https://google.github.io/oss-fuzz/). More references are at the end of this page. For googlers, please refer to evmaus@ for links to presentation of ZetaSQL fuzzing introduction.

The documentation also assumes that reader is comfortable working with [Bazel](https://bazel.build/), and reading `BUILD` file. Since the compilation detail is too remotely related to library itself, we will not go over how to set up build correctly, but to refer readers to the example `BUILD` files.

#### What is FAIR?

Fuzzers defined in ZetaSQL project currently has a mixed usage of both native libfuzzer interface for primitive fuzzing as well as Libprotobuf-mutator [(LPM)](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#protocol-buffers-as-intermediate-format) interface for structure aware fuzzing. Additionally, many fuzzers behave in fairly similar ways that they all extract some arguments from the test input and apply them to the tested API. FAIR library deconstructs a general fuzzer into four components and increasing reuse of existing components through composition.

Specifically, FAIR is short for 

- `FuzzTarget`, an abstraction for any ZetaSQL API to be fuzzed. It encapsulates the logic of setting up calls to ZetaSQL API given correct arguments. During fuzzing, arguments of the API calls can be extracted by visiting available `zetasql_fuzzer::Argument`. It is a Visitor to `zetasql_fuzzer::Argument`.
- `Argument`, an abstraction for any value that is extracted from the fuzzing input of `InputType` in `zetasql_fuzzer::Run` routine, and is to be applied to some `zetasql_fuzzer::FuzzTarget` in a fuzzing test. It is a Visitable to `zetasql::FuzzTarget`.
  - `Extractor`, a function that can extract some `Argument` from an input of `InputType`. The <a id='sig'>signature</a> should be compatible to `std::function<std::unique_ptr<zetasql_fuzzer::Argument>(const InputType&)>`
- `Input`, an abstraction for any input passed into `zetasql_fuzzer::Run` routine. Current implementation uses template for various input type.
- `Runner`, an abstraction for fuzzing test routine. Currently implemented as `zetasql_fuzzer::Run`.

#### How to use FAIR?

Let's study `simple_evaluator_fuzzer.cc` and `pipelined_expression_fuzzer.cc` as examples. To declare a fuzzer in ZetaSQL, developer should first include `fuzzer_macro.h`, then either choose `ZETASQL_SIMPLE_FUZZER` macro for fuzzing raw test inputs as strings, or `ZETASQL_PROTO_FUZZER` macro for fuzzing structure-aware with LPM interface. 

In `simple_evaluator_fuzzer.cc`, we have 

```c++
using zetasql_fuzzer::PreparedExpressionTarget;
using zetasql_fuzzer::SQLStringArg;

ZETASQL_SIMPLE_FUZZER(PreparedExpressionTarget, std::make_unique<SQLStringArg, const std::string&>);
```

`ZETASQL_SIMPLE_FUZZER` takes the first argument as the concrete subclass of `FuzzTarget`, and all the rest arguments as `Extractor`s, which as we can confirm here is compatible to defined [type signature](#sig). 
