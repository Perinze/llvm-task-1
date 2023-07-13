use std::collections::HashMap;
use std::ffi::{c_void};
use std::ptr::null_mut;
//use std::sync::{Once, RwLock};
use std::sync::Once;
//use anyhow::{Error, Result};
use nix::libc::{free, malloc};

/// The code in this file is just a skeleton. You are allowed (and encouraged!)
/// to change if it doesn't fit your needs or ideas.

static mut SHADOW: *mut Shadow = null_mut();
static INIT: Once = Once::new();

#[no_mangle]
pub extern "C" fn __runtime_init() {
}

#[no_mangle]
pub extern "C" fn __runtime_cleanup() {
}

#[no_mangle]
pub extern "C" fn __runtime_check_addr(ptr: *mut c_void, size: u64) {
    let shadow_value = get_shadow().get_shadow(ptr as u64);
    if shadow_value < 0 {
        Shadow::report_error()
    } else if shadow_value > 0 && Shadow::slow_path_check(shadow_value, ptr as u64, size) {
        Shadow::report_error()
    }
}

#[no_mangle]
pub extern "C" fn __runtime_stack_alloc(ptr: *mut c_void, size: u64) {
    let ptr_u64 = ptr as u64;
    let mut p = ptr_u64;
    while p < ptr_u64 + size {
        let rest = ptr_u64 + size - p;
        if rest >= 8 {
            get_shadow().set_shadow(p, 0);
        } else {
            get_shadow().set_shadow(p, rest as i8);
        }
        p += 8;
    }
}

#[no_mangle]
pub extern "C" fn __runtime_malloc(size: usize) -> *mut c_void {
    let size_u64 = size as u64;
    unsafe {
        let mem = malloc(size);

        let mem_u64 = mem as u64;
        let mut p = mem_u64;
        while p < mem_u64 + size_u64 {
            let rest = mem_u64 + size_u64 - p;
            if rest >= 8 {
                get_shadow().set_shadow(p, 0);
            } else {
                get_shadow().set_shadow(p, rest as i8);
            }
            p += 8;
        }

        mem
    }
}

#[no_mangle]
pub extern "C" fn __runtime_free(ptr: *mut c_void) {
    let mut p = ptr as u64;
    unsafe {
        while get_shadow().get_shadow(p) == 0 {
            get_shadow().set_shadow(p, -1);
            p += 8;
        }
        if get_shadow().get_shadow(p) > 0 {
            get_shadow().set_shadow(p, -1);
        }
        free(ptr);
    }
}

fn get_shadow() -> &'static mut Shadow {
    unsafe {
        INIT.call_once(|| {
            SHADOW = Box::into_raw(Box::new(Shadow::new()))
        });
        &mut *SHADOW
    }
}

struct Shadow {
    map: HashMap<u64, i8>,
}

impl Shadow {
    fn new() -> Shadow {
        Shadow {
            map: HashMap::new(),
        }
    }

    fn mem_to_shadow(ptr: u64) -> u64 {
        ptr >> 3
    }

    fn slow_path_check(shadow_value: i8, addr: u64, k: u64) -> bool{
        let last_access_byte = ((addr & 7) + k - 1) as i8;
        last_access_byte >= shadow_value
    }

    fn report_error() {
        eprintln!("Illegal memory access");
        std::process::exit(1);
    }

    fn set_shadow(&mut self, p: u64, shadow_value: i8) {
        let shadow_key = Self::mem_to_shadow(p);
        self.map.insert(shadow_key, shadow_value);
    }

    fn get_shadow(&self, p: u64) -> i8 {
        let shadow_key: u64 = Self::mem_to_shadow(p);
        match self.map.get(&shadow_key) {
            None => -1,
            Some(v) => *v,
        }
    }
}