#![no_std]
#![no_main]
#![allow(bad_style)]

#[cfg(not(all(target_env = "msvc", target_arch = "x86", target_os = "windows")))]
compile_error!("Platform not supported!");

use core::arch::asm;
use core::mem;
use core::ptr;

use crate::win32::{
    c_char, c_void, BOOL, CHAR, DLL_PROCESS_ATTACH, DWORD, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_HEADER,
    IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS32,
    IMAGE_TLS_DIRECTORY32, LDR_DATA_TABLE_ENTRY, LPCSTR, LPVOID, PEB, PIMAGE_TLS_CALLBACK,
    ULONG_PTR, WORD,
};

mod win32;

type DllEntryPoint = unsafe extern "system" fn(LPVOID, DWORD, LPVOID) -> BOOL;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;
fn IMAGE_SNAP_BY_ORDINAL32(ordinal: u32) -> bool {
    (ordinal & IMAGE_ORDINAL_FLAG32) != 0
}

const fn fx_hash_step(state: u32, x: u32) -> u32 {
    const K: u32 = 0x517cc1b7;
    (state.rotate_left(5) ^ x).wrapping_mul(K)
}

const fn fx_hash(input: &[u8]) -> u32 {
    let mut state = 0;
    let mut i = 0;
    while i < input.len() {
        state = fx_hash_step(state, input[i] as u32);
        i += 1;
    }
    state
}

const HASH_LOADLIBRARYA: u32 = fx_hash(b"LoadLibraryA");
const HASH_GETPROCADDRESS: u32 = fx_hash(b"GetProcAddress");

unsafe fn fx_hash_buf(mut input: *const c_char) -> u32 {
    let mut state = 0;
    while *input != 0 {
        state = fx_hash_step(state, *input as u32);
        input = input.add(1);
    }
    state
}

fn get_peb() -> *const PEB {
    let peb: *mut PEB;
    unsafe {
        asm!(
            "mov {}, fs:[0x30]",
            out(reg) peb,
            options(pure, nomem, nostack)
        );
    }

    peb
}

unsafe fn get_proc_address(dll: *const u8, target_hash: u32) -> *const c_void {
    let dos_header = &*(dll as *const IMAGE_DOS_HEADER);
    let nt_headers = &*(dll.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS32);

    let optional_header = &nt_headers.OptionalHeader;
    let export_dir_entry = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_dir =
        &*(dll.add(export_dir_entry.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY);

    let name_rva_table = dll.add(export_dir.AddressOfNames as usize) as *const DWORD;
    let ordinal_table = dll.add(export_dir.AddressOfNameOrdinals as usize) as *const WORD;
    let function_rva_table = dll.add(export_dir.AddressOfFunctions as usize) as *const DWORD;
    for name_idx in 0..export_dir.NumberOfNames {
        let name = dll.add(*name_rva_table.add(name_idx as usize) as usize) as *const c_char;

        if fx_hash_buf(name) == target_hash {
            // found it :3
            let ordinal = *(ordinal_table.add(name_idx as usize));

            return dll.add(*function_rva_table.add(ordinal as usize) as usize) as *const c_void;
        }
    }

    return ptr::null();
}

#[allow(unused_macros)]
macro_rules! regdebug {
    ($x:expr) => {{
        asm!(
            "mov eax, {}",
            "int3",
            in(reg) $x,
        );
    }};

    // ($x:expr, $y:expr) => {{
    //     asm!(
    //         "mov eax, {0}",
    //         "mov ecx, {1}",
    //         "int3",
    //         in(reg) $x,
    //         in(reg) $y,
    //     );
    // }};
}

#[allow(unused_macros)]
macro_rules! breakme {
    () => {{
        asm!("int3");
    }};
}

#[no_mangle]
pub unsafe extern "C" fn _shellcode(base: *const u8) {
    let modlist = &(*((*get_peb()).Ldr)).InMemoryOrderModuleList;
    let mod_kernel32 =
        &*((*((*(modlist.Flink)).Flink)).Flink.offset(-1) as *mut LDR_DATA_TABLE_ENTRY);
    let kernel32_dll = mod_kernel32.DllBase as *const u8;

    let proc_loadlibrarya: win32::LoadLibraryA =
        mem::transmute(get_proc_address(kernel32_dll, HASH_LOADLIBRARYA));
    let proc_getprocaddress: win32::GetProcAddress =
        mem::transmute(get_proc_address(kernel32_dll, HASH_GETPROCADDRESS));

    let dos_header = &*(base as *const IMAGE_DOS_HEADER);
    let nt_headers: &IMAGE_NT_HEADERS32 =
        &*(base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS32);
    let optional_header = &nt_headers.OptionalHeader;

    let import_dir_entry = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

    if import_dir_entry.Size > 0 {
        let mut import_descr =
            base.add(import_dir_entry.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*import_descr).Name != 0 {
            let modname: *const CHAR = base.add((*import_descr).Name as usize) as _;
            let dll = proc_loadlibrarya(modname);

            let mut thunk_ref =
                base.add((*import_descr).OriginalFirstThunk as usize) as *mut ULONG_PTR;
            let mut func_ref = base.add((*import_descr).FirstThunk as usize) as *mut ULONG_PTR;
            if thunk_ref.is_null() {
                thunk_ref = func_ref;
            }

            while *thunk_ref != 0 {
                if IMAGE_SNAP_BY_ORDINAL32(*thunk_ref as u32) {
                    // ordinal thunk
                    *func_ref =
                        proc_getprocaddress(dll, mem::transmute(*thunk_ref & 0xffff)) as ULONG_PTR;
                } else {
                    // string thunk
                    let namedimport = &*(base.add(*thunk_ref) as *const IMAGE_IMPORT_BY_NAME);
                    *func_ref = proc_getprocaddress(dll, &namedimport.Name as LPCSTR) as ULONG_PTR;
                }

                thunk_ref = thunk_ref.add(1);
                func_ref = func_ref.add(1);
            }

            import_descr = import_descr.add(1);
        }
    }

    let tls_dir_entry = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];
    if tls_dir_entry.Size > 0 {
        let tls_dir =
            &*(base.add(tls_dir_entry.VirtualAddress as usize) as *const IMAGE_TLS_DIRECTORY32);
        let mut callback = tls_dir.AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;
        while *(callback as *const DWORD) != 0 {
            (*callback)(base as *mut _, DLL_PROCESS_ATTACH, ptr::null_mut());

            callback = callback.add(1);
        }
    }

    let dllmain: DllEntryPoint =
        mem::transmute(base.add(optional_header.AddressOfEntryPoint as usize));
    dllmain(base as *mut _, DLL_PROCESS_ATTACH, ptr::null_mut());
}
