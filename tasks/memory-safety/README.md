# LLVM Memory Safety Pass

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
opt -load-pass-plugin build/libMemorySafety.so -passes=memory-safety -S ../../tests/memory-safety/build/malloc.ll
```
