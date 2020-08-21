# Documentation of ZetaSQL Fuzzing Library (FAIR)

## Code Deprecation and Notes

As part of the experimental code, `zetasql_expression_fuzzer.cc` has been replaced by `pipelined_expression_fuzzer.cc` but with FAIR library integration. `zetasql_expression_fuzzer.cc` and its dependencies exists only for existing bug reproduction. Future developer should model after `pipelined_expression_fuzzer.cc` for correct use of FAIR library.

The current Bazel build dependency isn't exactly at its finest, and combining with `fuzzer_macro.h`, every fuzzer will be compiled with `libprotobuf-mutator` dependency whether it's defined as a `cc_proto_fuzzer` or `cc_fuzzer`. Effort to separate the dependency is welcomed.

## FAIR Library

### Before you start

This documentation assumes that readers know how to correctly configure ZetaSQL project and would like to know how to contribute to ZetaSQL fuzzing specifically. Developers who don't have background of Fuzzing Tests or OSS-Fuzz are suggested to take quick tutorials [here](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md) and [here](https://google.github.io/oss-fuzz/). More references are at the end of this page. For googlers, please refer to evmaus@ for links to presentation of ZetaSQL fuzzing introduction.

The documentation also assumes that readers are comfortable working with [Bazel](https://bazel.build/), and reading `BUILD` file. Since the compilation detail is too remotely related to library itself, we will not go over how to set up build correctly, but to refer readers to the example `BUILD` files.

### What is FAIR?

Fuzzers defined in ZetaSQL project currently has a mixed usage of both native libfuzzer interface for primitive fuzzing as well as Libprotobuf-mutator [(LPM)](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#protocol-buffers-as-intermediate-format) interface for structure aware fuzzing. Additionally, many fuzzers behave in fairly similar ways that they all extract some arguments from the test input and apply them to the tested API. FAIR library deconstructs a general fuzzer into four components and increasing reuse of existing components through composition.

Specifically, FAIR is short for 

- `FuzzTarget`, an abstraction for any ZetaSQL API to be fuzzed. It encapsulates the logic of setting up calls to ZetaSQL API given correct arguments. During fuzzing, arguments of the API calls can be extracted by visiting available `zetasql_fuzzer::Argument`. It is a Visitor to `zetasql_fuzzer::Argument`.
- <a id='arg'>`Argument`</a>, an abstraction for any value that is extracted from the fuzzing input of `InputType` in `zetasql_fuzzer::Run` routine, and is to be applied to some `zetasql_fuzzer::FuzzTarget` in a fuzzing test. It is a Visitable to `zetasql::FuzzTarget`.
  - `Extractor`, a function that can extract some `Argument` from an input of `InputType`. The <a id='sig'>signature</a> should be compatible to `std::function<std::unique_ptr<zetasql_fuzzer::Argument>(const InputType&)>`
- `Input`, an abstraction for any input passed into `zetasql_fuzzer::Run` routine. Current implementation uses template for various input type.
- `Runner`, an abstraction for **engine-agnostic** fuzzing test routine. Currently implemented as `zetasql_fuzzer::Run`. See [The macro and Runner](#the-macro-and-runner) for correct use. 

### How to use FAIR?

#### The macro and Runner

Let's study `simple_evaluator_fuzzer.cc` and `pipelined_expression_fuzzer.cc` as examples. To declare a fuzzer in ZetaSQL, developer should first include `fuzzer_macro.h`, then either choose `ZETASQL_SIMPLE_FUZZER` macro for fuzzing raw test inputs as strings, or `ZETASQL_PROTO_FUZZER` macro for fuzzing structure-aware with LPM interface (see [LPM Backend for Structure-aware Fuzzing](#lpm-backend-for-structure-aware-fuzzing)). 

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

Under the hood, these macros instantiate the fuzz target interface for `libfuzzer` and LPM respectively, and then invoke `zetasql_fuzzer::Run` in the instantiation, with test input of either `std::string` in `ZETASQL_SIMPLE_FUZZER` or the supplied type (e.g., `Expression`) in `ZETASQL_PROTO_FUZZER`. See also [input](#the-input) section for more detail about using different types of inputs.

The point of `zetasql_fuzzer::Run` being engine agnostic is that we want to separate the engine setup from fuzzing test logic, so that the latter can be reused in different engine in the future. As a result, however, `zetasql_fuzzer::Run` **must** be used inside an interface provided by a fuzzing engine. Using a macro is therefore recommended to avoid the hassle of learning engine interface. 

Addtionally, there can be **exactly one** engine interface (therefore, one macro) be instantiated per fuzzing test. This is because every fuzzing test will be compiled into a standalone binary. Declaring two or more fuzzing tests in a fuzzer source file causes compilation error. 

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

As defined earlier, FuzzTarget is an abstraction for any ZetaSQL API to be fuzzed. In a declared fuzzer with FAIR, a `FuzzTarget` object will be instantiated and executed after all available `Argument`s have been visited. `PreparedExpressionTarget` is really just a concrete subclass of `FuzzTarget` that knows how to execute `PreparedExpression::Execute` function. Now take a look at the implementation of `PreparedExpressionTarget`,

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

We see that the `PreparedExpressionTarget` knows exactly how to get the argument value from available `zetasql_fuzzer::Argument`, and how to execute the fuzzed API. Additionally, notice that `PreparedExpressionTarget` doesn't override `#Visit(ParameterValueListArg& arg)` function. This means that it doesn't know how to get the argument, because the underlying calls never need it! This is convenient because `FuzzTarget.h` provides a default implementation, so we don't need to handle arguments irrelavant of the fuzzed API. If an unhandled argument is accidentally introduced, the program will crash and complain so we know that we set up the fuzzer incorrectly. 

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

class SQLStringArg : public TypedArg<std::string> {
 public:
  using TypedArg::TypedArg;
  void Accept(zetasql_fuzzer::FuzzTarget& function) override {
    function.Visit(*this);
  }
};
```

`Argument` is implemented as a type-erased container, and combined with Visitor pattern, `Argument` yields great flexibility for both `FuzzTarget` and `Extractor`. `Extractor` can be as simple as `std::make_unique<SQLStringArg, const std::string&>` in the case of `simple_evaluator_fuzzer.cc`, or as complicated as `GetParam<As::PARAMETERS>` in `piplined_expression_fuzzer.cc`. For LPM based structure aware fuzzer, see [LPM Backend for Structure-aware Fuzzing](#lpm-backend-for-structure-aware-fuzzing). Supporting more `Extractor` and `Argument` should be fairly easy by modeling after current implementation, but can also flexible due to little constraints in the type signature. 

#### The Input

Test input are currently directly feeded into `zetasql_fuzzer:Run` with parameterized `InputType` type. As such, input itself must be a single object of `InputType`, and is compatible with the signature type of supplied `Extractor`s. We have two options for test input as of now: `std::string` input that wraps directly the raw test bytes array from `libfuzzer` engine, or defined proto messages. See [macro](#the-macro-and-runner) section for how to use wire up these two kinds of fuzzers. 

To accomondate for new kinds of input, `InputType` definition and/or necessary argument `Extractor` should be supplied. If the input is neither of simple wrapper of the raw bytes, or some protobuf message, new macros may be required to correctly wire up correctly the desired input, fuzzing engine interface, and `zetasql_fuzzer::Run` interface together. We recommend readers to model after code in `fuzzer_macro.h` in this situation. For using or extending new protobuf message input, see [LPM Backend for Structure-aware Fuzzing](#lpm-backend-for-structure-aware-fuzzing)

## LPM Backend for Structure-aware Fuzzing

ZetaSQL Fuzzing project uses Libprotobuf-mutator [(LPM)](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#protocol-buffers-as-intermediate-format) as the structure aware fuzzing infrastructure. As a short introduction, Google protobuf messages provides a nice way to represent data encoding schema and LPM takes advantage of it by parsing fuzzing inputs into some protobuf message, and mutating only the content of the protobuf message. As the user of LPM, we only need to decode the protobuf correctly (i.e., extract useful data following the defined schema) to perform structure aware fuzzing. This approach aligns fairly well with representing and mutating SQL abstract syntax tree (AST). 

### Input

LPM supplies defined protobuf message as argument to the declared fuzz targets. As explained earlier, the message type (i.e., class) should be specified in `ZETASQL_PROTO_FUZZER` as the first argument. Doing so tells the engine what message type to use for this fuzz test.  Currently supported AST structures are binary arithmetic expressions with arbitrary literals or variable (as column or parameter), defined in `protobuf/zetasql_expression_grammar.proto` and `protobuf/parameter_grammar.proto`. Future extension on SQL language feature can model after current solution.

### Argument Extractors

`protobuf/argument_extractors.h` provides a comprehensive list of `zetasql_fuzzer::Extractor`s currently supported. Internally they use implementations of `zetasql_fuzzer::internal::ProtoExprExtractor` or `zetasql_fuzzer::internal::LiteralExtractor` in `protobuf/internal/syntax_tree_visitor.h` that defines helper classes to correctly extract encoded data from protobuf message, such as the SQL statement string or parameter values. `protobuf/internal/` directory curates all implementations of `zetasql_fuzzer::internal::Extractor` interfaces.

```c++
template <typename Result>
class Extractor {
 public:
  virtual ~Extractor() = default;
  virtual const Result& Data() = 0;
};

template <typename Result>
class LiteralExtractor : public Extractor<Result> {
 public:
  virtual ~LiteralExtractor() = default;
  virtual void Extract(const parameter_grammar::Literal& literal) = 0;
  virtual void Extract(const parameter_grammar::IntegerLiteral& integer) = 0;
  virtual void Extract(const parameter_grammar::NumericLiteral& numeric) = 0;
};

template <typename Result>
class ProtoExprExtractor : public Extractor<Result> {
 public:
  virtual ~ProtoExprExtractor() = default;

  virtual void Extract(const parameter_grammar::Value& value) = 0;
  virtual void Extract(const zetasql_expression_grammar::Expression& expr) = 0;
  virtual void Extract(const zetasql_expression_grammar::CompoundExpr& comp_expr) = 0;
  virtual void Extract(const zetasql_expression_grammar::BinaryOperation& binary_operation) = 0;
};
```

Notice that `zetasql_fuzzer::internal::Extractor` is different from `zetasql_fuzzer::Extractor`, the latter uses the former as the implementation dependency to actually extract the `zetasql_fuzzer::Argument` from any protobuf message.
