#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
/// The code in this file is just a skeleton. You are allowed (and encouraged!)
/// to change if it doesn't fit your needs or ideas.

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>

//constexpr unsigned long long __shadow_size = 4294967296; // 4GB
//constexpr unsigned long long __shadow_size = 4096; // 4KB

//char *__shadow = nullptr;

std::map<char*, char> __shadow;

static char *__mem_to_shadow(void *ptr);
static bool __slow_path_check(char shadow_value, char *addr, size_t k);
static void __report_error();
static void __set_shadow(char *p, char shadow_value);
static char __get_shadow(char *p);

extern "C" {
__attribute__((used))
void __runtime_init() {
}

__attribute__((used))
void __runtime_cleanup() {
    fprintf(stderr, "log: shadow free\n");
    __shadow.clear();
}

__attribute__((used))
void __runtime_check_addr(void *ptr, size_t size) {
    fprintf(stderr, "log: check addr %p %lu\n", ptr, size);
    char shadow_value = __get_shadow((char*)ptr);
    fprintf(stderr, "log: shadow value is %u\n", (unsigned)shadow_value);
    if (shadow_value < 0) {
        fprintf(stderr, "log: shadow value is negative\n");
        __report_error();
    } else if (shadow_value) {
        if (__slow_path_check(shadow_value, (char*)ptr, size)) {
            __report_error();
        }
    }
}

__attribute__((used))
void *__runtime_malloc(size_t size) {
    fprintf(stderr, "log: runtime malloc\n");
    char *mem = (char *) malloc(size);
    if (mem == nullptr) {
        fprintf(stderr, "log: malloc return nullptr\n");
    }
    fprintf(stderr, "log: mem is at %p with size %u\n", mem, size);
    fprintf(stderr, "log: end is %p\n", mem + size);
    fprintf(stderr, "log: setting shadow\n");
    for (char *p = mem; p < mem + size; p += 8) {
        fprintf(stderr, "log: current block is %p\n", p);
        auto rest = mem + size - p;
        if (rest >= 8) {
            fprintf(stderr, "log: large enough, writing 0 to shadow\n");
            __set_shadow(p, 0);
        } else { // rest < 8
            fprintf(stderr, "log: less than 8, writing %u to shadow\n", (unsigned)rest);
            __set_shadow(p, (char) rest);
        }
    }
    fprintf(stderr, "log: malloc wrapper return\n");
    return mem;
}

__attribute__((used))
void __runtime_free(void *ptr) {
    char *p = (char *) ptr;
    fprintf(stderr, "log: ptr %p\n", ptr);
    while (__get_shadow(p) == 0) {
        __set_shadow(p, -1);
        p += 8;
    }
    if (__get_shadow(p) > 0) {
        __set_shadow(p, -1);
    }
    free(ptr);
}
}

static char *__mem_to_shadow(void *ptr) {
    fprintf(stderr, "log: %p => %p\n", ptr, (char*)((unsigned long)ptr >> 3));
    return (char*)((unsigned long long)ptr >> 3);
}

static bool __slow_path_check(char shadow_value, char *addr, size_t k) {
    auto last_access_byte = ((unsigned long long)addr & 7) + k - 1;
    return last_access_byte >= shadow_value;
}

static void __report_error() {
    fprintf(stderr, "Illegal memory access\n");
    exit(1);
}

static void __set_shadow(char *p, char shadow_value) {
    fprintf(stderr, "log: set shadow %p by value %u\n", p, (unsigned)shadow_value);
    char *shadow_addr = __mem_to_shadow(p);
    fprintf(stderr, "log: shadow entry is %p\n", p, shadow_addr);
    if (shadow_value < 0) {
        fprintf(stderr, "log: shadow value is negative, so erase the entry %p\n", shadow_addr);
        __shadow.erase(shadow_addr);
        fprintf(stderr, "log: %p erased from map\n", shadow_addr);
    } else {
        __shadow[shadow_addr] = shadow_value;
        fprintf(stderr, "log: entry %p set to %u\n", shadow_addr, (unsigned) shadow_value);
    }
    fprintf(stderr, "log: set shadow value done\n", p, (unsigned)shadow_value);
}

static char __get_shadow(char *p) {
    char *shadow_addr = __mem_to_shadow(p);
    if (__shadow.find(shadow_addr) == __shadow.end()) {
        return -1;
    } else {
        return __shadow[shadow_addr];
    }
}

#pragma clang diagnostic pop
