#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
/// The code in this file is just a skeleton. You are allowed (and encouraged!)
/// to change if it doesn't fit your needs or ideas.

#include <cstdlib>
#include <cstring>
#include <iostream>

constexpr unsigned long long __shadow_size = 4294967296; // 4GB
char *__shadow = nullptr;

static char *__mem_to_shadow(void *ptr);
static bool __slow_path_check(char shadow_value, char *addr, size_t k);
static void __report_error();
static void __set_shadow(char *p, char shadow_value);
static char __get_shadow(char *p);

extern "C" {
__attribute__((used))
void __runtime_init() {
    __shadow = (char*) malloc(__shadow_size);
    memset(__shadow, -1, __shadow_size);
}

__attribute__((used))
void __runtime_cleanup() {
    free(__shadow);
}

__attribute__((used))
void __runtime_check_addr(void *ptr, size_t size) {
    char *addr = __mem_to_shadow(ptr);
    char shadow_value = *addr;
    if (shadow_value) {
        if (__slow_path_check(shadow_value, addr, size)) {
            __report_error();
        }
    }
}

__attribute__((used))
void *__runtime_malloc(size_t size) {
    auto padded_size = size + 32;
    char *mem = (char*) malloc(padded_size);
    char *ptr = mem + 16;
    for (char *p = mem; p < ptr; p += 8) {
        __set_shadow(p, -1);
    }
    for (char *p = ptr; p < ptr + size; p += 8) {
        auto rest = ptr + size - p;
        if (rest >= 8) {
            __set_shadow(p, 0);
        } else { // rest < 8
            __set_shadow(p, (char)rest);
        }
    }
    for (char *p = mem; p < ptr; p += 8) {
        __set_shadow(p, -1);
    }
    return ptr;
}

__attribute__((used))
void __runtime_free(void *ptr) {
    char *p = (char*)ptr;
    char *mem = p - 16;
    while (__get_shadow(p) == 0) {
        __set_shadow(p, -1);
        p += 8;
    }
    __set_shadow(p, -1);
    free(mem);
}

static char *__mem_to_shadow(void *ptr) {
    return (char*)(__shadow + ((unsigned long long)ptr >> 3));
}

static bool __slow_path_check(char shadow_value, char *addr, size_t k) {
    auto last_access_byte = ((unsigned long long)addr & 7) + k - 1;
    return last_access_byte >= shadow_value;
}

static void __report_error() {
    std::cerr << "Illegal memory access\n";
}

static void __set_shadow(char *p, char shadow_value) {
    char *shadow_addr = __mem_to_shadow(p);
    *shadow_addr = shadow_value;
}

static char __get_shadow(char *p) {
    char *shadow_addr = __mem_to_shadow(p);
    return *shadow_addr;
}

#pragma clang diagnostic pop
