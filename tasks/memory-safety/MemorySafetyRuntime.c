#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
/// The code in this file is just a skeleton. You are allowed (and encouraged!)
/// to change if it doesn't fit your needs or ideas.

#include <stddef.h>

__attribute__((used))
extern void __runtime_init() {}

__attribute__((used))
extern void __runtime_cleanup() {}

__attribute__((used))
extern void __runtime_check_addr(/* your arguments */) {}

__attribute__((used))
extern void *__runtime_malloc(size_t size) {
    return NULL;
}

__attribute__((used))
extern void __runtime_free(void *ptr) {}

#pragma clang diagnostic pop
