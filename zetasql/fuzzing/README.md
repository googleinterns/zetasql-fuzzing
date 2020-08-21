# Documentation of ZetaSQL Fuzzing Library (FAIR)

## Code Deprecation and Notes

As part of the experimental code, `zetasql_expression_fuzzer.cc` has been replaced by `pipelined_expression_fuzzer.cc` but with FAIR library integration. `zetasql_expression_fuzzer.cc` and its dependencies existed only for convenient bug reproduction. Future developer should model after `pipelined_expression_fuzzer.cc` for correct use of FAIR library.

The current Bazel build dependency isn't exactly at its finest, and combining with `fuzzer_macro.h`, every fuzzer will be compiled with `libprotobuf-mutator` dependency whether it's defined as a `cc_proto_fuzzer` or `cc_fuzzer`. Effort to separate the dependency is welcomed.

## FAIR Library

### Before you start

This documentation assumes that readers know how to correctly configure ZetaSQL project and would like to know how to contribute to ZetaSQL fuzzing specifically. Developers who don't have background of Fuzzing Tests or OSS-Fuzz are suggested to take quick tutorials [here](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md) and [here](https://google.github.io/oss-fuzz/). More references are at the end of this page. For googlers, please refer to evmaus@ for links to presentation of ZetaSQL fuzzing introduction.

The documentation also assumes that reader is comfortable working with [Bazel](https://bazel.build/), and reading `BUILD` file. Since the compilation detail is too remotely related to library itself, we will not go over how to set up build correctly, but to refer readers to the example `BUILD` files.

### What is FAIR?

Fuzzers defined in ZetaSQL project currently has a mixed usage of both native libfuzzer interface for primitive fuzzing as well as Libprotobuf-mutator [(LPM)](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#protocol-buffers-as-intermediate-format) interface for structure aware fuzzing. Additionally, many fuzzers behave in fairly similar ways that they all extract some arguments from the test input and apply them to the tested API. FAIR library deconstructs a general fuzzer into four components and increasing reuse of existing components through composition.

Specifically, FAIR is short for 

- `FuzzTarget`, an abstraction for any ZetaSQL API to be fuzzed. It encapsulates the logic of setting up calls to ZetaSQL API given correct arguments. During fuzzing, arguments of the API calls can be extracted by visiting available `zetasql_fuzzer::Argument`. It is a Visitor to `zetasql_fuzzer::Argument`.
- <a id='arg'>`Argument`</a>, an abstraction for any value that is extracted from the fuzzing input of `InputType` in `zetasql_fuzzer::Run` routine, and is to be applied to some `zetasql_fuzzer::FuzzTarget` in a fuzzing test. It is a Visitable to `zetasql::FuzzTarget`.
  - `Extractor`, a function that can extract some `Argument` from an input of `InputType`. The <a id='sig'>signature</a> should be compatible to `std::function<std::unique_ptr<zetasql_fuzzer::Argument>(const InputType&)>`
- `Input`, an abstraction for any input passed into `zetasql_fuzzer::Run` routine. Current implementation uses template for various input type.
- `Runner`, an abstraction for fuzzing test routine. Currently implemented as `zetasql_fuzzer::Run`.

### How to use FAIR?

#### The macro

Let's study `simple_evaluator_fuzzer.cc` and `pipelined_expression_fuzzer.cc` as examples. To declare a fuzzer in ZetaSQL, developer should first include `fuzzer_macro.h`, then either choose `ZETASQL_SIMPLE_FUZZER` macro for fuzzing raw test inputs as strings, or `ZETASQL_PROTO_FUZZER` macro for fuzzing structure-aware with LPM interface. 

In `simple_evaluator_fuzzer.cc`, we have 

```c++
using zetasql_fuzzer::PreparedExpressionTarget;
using zetasql_fuzzer::SQLStringArg;

ZETASQL_SIMPLE_FUZZER(PreparedExpressionTarget, std::make_unique<SQLStringArg, const std::string&>);
```

`ZETASQL_SIMPLE_FUZZER` takes the first argument as the concrete subclass of `FuzzTarget`, and all the rest arguments as `Extractor`s, which as we can confirm here is compatible to defined [type signature](#sig). 

In `pipelined_expression_fuzzer.cc`, we have

```c++
using zetasql_expression_grammar::Expression;
using zetasql_fuzzer::GetParam;
using zetasql_fuzzer::GetProtoExpr;
using zetasql_fuzzer::PreparedExpressionTarget;

using As = zetasql_fuzzer::ParameterValueAs;

ZETASQL_PROTO_FUZZER(Expression, PreparedExpressionTarget, GetProtoExpr,
                     GetParam<As::COLUMNS>, GetParam<As::PARAMETERS>);
```

The code looks intimidating, but really what it does is that `ZETASQL_PROTO_FUZZER` takes the first argument as the `InputType` (i.e., we declare the current fuzzer input is of type `Expression`), the second argument as the concrete subclass of `FuzzTarget`, and all the rest as `Extractor`s, compatible to defined [type signature](#sig).

#### The Fuzz Target

So what is the `PreparedExpressionTarget`? Let's take a look at `component/fuzz_targets/fuzz_target.h` first.

```c++
class FuzzTarget {
 public:
  virtual ~FuzzTarget() = default;
  virtual void Visit(SQLStringArg& arg) { AbortVisit("SQLStringArg&"); }
  virtual void Visit(ParameterValueMapArg& arg) { AbortVisit("ParameterValueMapArg&"); }
  virtual void Visit(ParameterValueListArg& arg) { AbortVisit("ParameterValueListArg&"); 
  virtual void Execute() = 0;
```

As defined earlier, FuzzTarget is an abstraction for any ZetaSQL API to be fuzzed. `PreparedExpressionTarget` is really just a concrete subclass of `FuzzTarget` that knows how to execute `PreparedExpression::Execute` function. Now take a look at the implementation of `PreparedExpressionTarget`,

```c++
// component/fuzz_targetsprepared_expression_target.h
class PreparedExpressionTarget : public FuzzTarget {
 public:
  void Visit(SQLStringArg& sql) override;
  void Visit(ParameterValueMapArg& arg) override;
  void Execute() override;

 private:
  std::unique_ptr<std::string> sql_expression_;
  std::unique_ptr<zetasql::ParameterValueMap> columns_;
  std::unique_ptr<zetasql::ParameterValueMap> parameters_;
};

// component/fuzz_targetsprepared_expression_target.cc
void PreparedExpressionTarget::Visit(SQLStringArg& arg) {
  sql_expression_ = arg.Release().ValueOrDie();
}

...

void PreparedExpressionTarget::Execute() {
  if (!sql_expression_) {
    LOG(FATAL) << "SQL expression not found";
  }
  zetasql::PreparedExpression expression(*sql_expression_);
  expression.Execute(GetOrDefault(columns_), GetOrDefault(parameters_));
}
```

We see that the PreparedExpressionTarget knows exactly how to get the argument value from available `zetasql_fuzzer::Argument`, and how to execute the fuzzed API. Additionally, notice that `PreparedExpressionTarget` doesn't override `#Visit(ParameterValueListArg& arg)` function. This means that it doesn't know how to get the argument, because the underlying calls never need it! This is convienient because `FuzzTarget.h` provides a default implementation, so we don't need to handle arguments irrelavant of the fuzzed API. If an unhandled argument is accidentally introduced, the program will crash and complain so we know that we set up the fuzzer incorrectly. 

#### The Argument & Extractors

According to the [defintion](#arg), `Argument`s are essentially value containers used by `FuzzTarget`. However, `Argument` is not aware of test input directly, but relies on `Extractor`s to do the translation work. As such, the modularization between `FuzzTarget` and `Extractor`s is guaranteed, so that `FuzzTarget` can be mix-and-matched with `Extractor`s for different inputs as long the resulting argument is compatible.  

```c++
class Argument {
 public:
  ...
  virtual void Accept(zetasql_fuzzer::FuzzTarget& function) = 0;
};

template <typename ArgType>
class TypedArg : public Argument {
 public:
  ...
  TypedArg(const ArgType& value) : argument_(std::make_unique<ArgType>(value)) {}
  TypedArg(ArgType&& value) : argument_(std::make_unique<ArgType>(value)) {}
  TypedArg(std::unique_ptr<ArgType> pointer) : argument_(std::move(pointer)) {}

  ...
  zetasql_base::StatusOr<std::unique_ptr<ArgType>> Release();

 private:
  std::unique_ptr<ArgType> argument_;
};
```

`Argument` is implemented as a type-erased container, and combined with Visitor pattern, `Argument` yields great flexibility for both `FuzzTarget` and `Extractor`. `Extractor` can be as simple as `std::make_unique<SQLStringArg, const std::string&>` in the case of `simple_evaluator_fuzzer.cc`, or as complicated as `GetParam<As::PARAMETERS>` in `piplined_expression_fuzzer`. For LPM based structure aware fuzzer, we refer readers to `protobuf/argument_extractors.h` for a comprehensive list of `Extractor`s currently supported. Supporting more `Extractor` and `Argument` should be fairly easy by modeling after current implementation, but can also flexible due to little constraints in the type signature. 

#### Input

#### Runner

## LPM Backend for Structure-aware Fuzzing

