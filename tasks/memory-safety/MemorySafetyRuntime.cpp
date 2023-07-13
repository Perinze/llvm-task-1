#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
/// The code in this file is just a skeleton. You are allowed (and encouraged!)
/// to change if it doesn't fit your needs or ideas.

#include <cstdlib>
#include <iostream>
#include <sys/mman.h>
#include <stdarg.h>

constexpr unsigned long __shadow_size = 0x7fffffffffff >> 3;
char* __shadow = nullptr;


static char *__mem_to_shadow(void *ptr);
static bool __slow_path_check(char *addr, size_t k);
static void __report_error();
static void __set_shadow(char *ptr, size_t len, bool valid);

#define DEBUG
void log(const char *format, ...) {
#ifdef DEBUG
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
#endif
}

extern "C" {
__attribute__((used))
void __runtime_init() {
    log("runtime init\n");
    __shadow = (char*)mmap(nullptr, __shadow_size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    log("shadow mem %p\n", __shadow);
}

__attribute__((used))
void __runtime_cleanup() {
    log("runtime cleanup\n");
    munmap(__shadow, __shadow_size);
}

__attribute__((used))
void __runtime_check_addr(void *ptr, size_t size) {
    log("runtime check addr\n");
    if (!__slow_path_check((char*)ptr, size)) {
        __report_error();
    }
}

__attribute__((used))
void *__runtime_stack_alloc(void *ptr, size_t size, size_t pad) {
    log("runtime stack alloc\n");
    //log("//log: runtime stack alloc\n");
    //log("//log: mem is at %p with size %u\n", ptr, size);
    //log("//log: end is %p\n", (char*)ptr + size);
    //log("//log: setting shadow\n");
    char *pad_low = (char*)ptr;
    auto mem = pad_low + pad;
    auto pad_up = pad_low + pad + size;
    __set_shadow(pad_low, pad, false);
    __set_shadow(mem, size, true);
    __set_shadow(pad_up, pad, false);
    //log("//log: stack alloc wrapper return\n");
    return mem;
}

__attribute__((used))
void *__runtime_malloc(size_t size) {
    log("runtime malloc\n");
    size = (size + 7) & (~7);
    auto padded_size = size + 64;
    char *mem = (char *) malloc(padded_size);
    //if (mem == nullptr) {
    //    //log("//log: malloc return nullptr\n");
    //}
    //log("//log: mem is at %p with size %u\n", mem, size);
    //log("//log: end is %p\n", mem + size);
    //log("//log: setting shadow\n");
    auto begin = mem;
    auto mid = mem + 32;
    auto ed = mem + padded_size - 32;
    __set_shadow(begin, 32, false);
    __set_shadow(mid, size, true);
    __set_shadow(ed, 32, false);
    *begin = size;
    //log("//log: malloc wrapper return\n");
    return mid;
}

__attribute__((used))
void __runtime_free(void *ptr) {
    log("runtime free\n");
    auto begin = ((char*)ptr - 32);
    auto size = *begin;
    __set_shadow((char*)ptr, size, false);
}
}

static char *__mem_to_shadow(void *ptr) {
    log("mem to shadow\n");
    return __shadow + ((size_t)ptr >> 3);
}

static bool __slow_path_check(char *addr, size_t k) {
    log("slow path check\n");
    auto shadow_addr = __mem_to_shadow(addr);
    auto shadow_value = *shadow_addr;
    if (shadow_value == 0) {
        return true;
    } else if (k < 8) {
        return ((size_t)addr & 7) + k <= shadow_value;
    } else {
        return false;
    }
}

static void __report_error() {
    fprintf(stderr, "Illegal memory access\n");
    exit(1);
}

static void __set_shadow(char *ptr, size_t len, bool valid) {
    log("set shadow\n");
    //log("//log: set shadow %p by value %u\n", p, (unsigned)shadow_value);
    auto shadow_addr = __mem_to_shadow(ptr);
    //log("//log: shadow entry is %p\n", p, shadow_addr);
    log("filling blk\n");
    size_t i = 0;
    while (len >= 8 and i <= len - 8) {
        char shadow_value;
        if (valid) shadow_value = 0;
        else shadow_value = -1;
        log("blk: %p\n", shadow_addr + (i >> 3));
        *(shadow_addr + (i >> 3)) = shadow_value;
        i += 8;
    }

    log("after filling blk\n");
    while (i < len) {
        auto ind = i >> 3;
        char bit = i & 7;
        auto shadow_value = *(shadow_addr + ind);
        char new_shadow_value;
        if (valid) {
            new_shadow_value = shadow_value & !(1 << bit);
        } else {
            new_shadow_value = shadow_value | (1 << bit);
        }
        *(shadow_addr + ind) = new_shadow_value;
        i++;
    }
    //log("//log: set shadow value done\n", p, (unsigned)shadow_value);
}

#pragma clang diagnostic pop
