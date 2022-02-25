#![no_std]
#![no_main]
#![allow(bad_style)]

use core::{arch::asm, ptr};
use core::mem;

use win32::{LPVOID, DWORD, BOOL, DLL_PROCESS_ATTACH};

use crate::win32::{IMAGE_IMPORT_DESCRIPTOR, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32, IMAGE_DIRECTORY_ENTRY_IMPORT, CHAR, ULONG_PTR, IMAGE_IMPORT_BY_NAME, c_char, LPCSTR};

mod win32;
mod iface;

type DllEntryPoint = unsafe extern "system" fn(LPVOID, DWORD, LPVOID) -> BOOL;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;
fn IMAGE_SNAP_BY_ORDINAL32(ordinal: u32) -> bool {
    (ordinal & IMAGE_ORDINAL_FLAG32) != 0
}

#[no_mangle]
pub unsafe extern "C" fn _shellcode(dat: *const iface::ShellcodeInput) {
    asm!("int3");

    let base = (*dat).base;
    let dos_header = &*(base as *const IMAGE_DOS_HEADER);
    let nt_headers: &IMAGE_NT_HEADERS32 = &*(base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS32);

    let optional_header = &nt_headers.OptionalHeader;

    let import_dir_entry = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir_entry.Size > 0 {
        let mut import_descr = base.add(import_dir_entry.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;
        
        while (*import_descr).Name != 0 {
            let modname: *const CHAR = base.add((*import_descr).Name as usize) as _;
            let dll = (*((*dat).load_library))(modname);

            let mut thunk_ref = base.add((*import_descr).OriginalFirstThunk as usize) as *mut ULONG_PTR;
            let mut func_ref  = base.add((*import_descr).FirstThunk as usize) as *mut ULONG_PTR;
            if thunk_ref.is_null() {
                thunk_ref = func_ref;
            }

            while *thunk_ref != 0 {
                if IMAGE_SNAP_BY_ORDINAL32(*thunk_ref as u32) { // ordinal thunk
                    *func_ref = (*((*dat).get_proc_addr))(dll, mem::transmute(*thunk_ref & 0xffff)) as ULONG_PTR;
                } else { // string thunk
                    let namedimport = &*(base.add(*thunk_ref) as *const IMAGE_IMPORT_BY_NAME);
                    *func_ref = (*((*dat).get_proc_addr))(dll, &namedimport.Name as LPCSTR) as ULONG_PTR;
                }

                thunk_ref = thunk_ref.add(1);
                func_ref = func_ref.add(1);
            }

            import_descr = import_descr.add(1);
        }
    }

    // TODO TLS

    let dllmain = base.add(optional_header.AddressOfEntryPoint as usize) as *const DllEntryPoint;
    (*dllmain)(base as *mut _, DLL_PROCESS_ATTACH, 0 as _);
}