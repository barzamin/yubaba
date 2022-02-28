#![allow(non_snake_case)]

#[cfg(not(all(target_env = "msvc", target_arch = "x86", target_os = "windows")))]
compile_error!("need to build as 32-bit win pe via msvc");

use std::{ffi::c_void, ptr};

use windows::Win32::{
    Foundation::{BOOL, HINSTANCE, PSTR},
    System::{LibraryLoader::DisableThreadLibraryCalls, SystemServices::DLL_PROCESS_ATTACH},
    UI::WindowsAndMessaging::{MessageBoxA, MB_OK},
};

#[no_mangle]
pub extern "stdcall" fn DllMain(dll_handle: HINSTANCE, reason: u32, _reserved: c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(dll_handle);
        }

        unsafe {
            MessageBoxA(
                None,
                PSTR(b"catboy injected!\0".as_ptr()),
                PSTR(b"woof!\0".as_ptr()),
                MB_OK,
            );
        }
    }

    true.into()
}
