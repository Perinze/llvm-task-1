# LLVM Dead Code Elimination Pass

<!-- 
Install the following extensions:

- CMake
- CMake Tools
- C/C++ Extension Pack
 -->

## Building

```shell
mkdir build
cd build
cmake -G Ninja ..
cd ..
ninja -Cbuild
```

## Running the pass

Note: You need `opt` from LLVM 16.0.0 or later, as the test cases contain the new opaque pointer type that was
introduced in LLVM 16.

```shell
opt -load-pass-plugin build/libDeadCodeElimination.dylib -passes=dead-code-elimination -S ../../tests/inputs/test-1.ll 
```
