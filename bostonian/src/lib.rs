#![allow(non_snake_case)]

use std::ffi::c_void;

use windows::Win32::{
    Foundation::{BOOL, HINSTANCE},
    System::{LibraryLoader::DisableThreadLibraryCalls, SystemServices::DLL_PROCESS_ATTACH},
};

#[no_mangle]
pub extern "stdcall" fn DllMain(dll_handle: HINSTANCE, reason: u32, _reserved: c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(dll_handle);
        }
    }

    true.into()
}
