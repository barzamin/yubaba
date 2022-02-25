use std::{ffi::c_void, ptr};

use tracing::trace;
use windows::Win32::{System::{Diagnostics::Debug::WriteProcessMemory, Memory::{VIRTUAL_ALLOCATION_TYPE, PAGE_PROTECTION_FLAGS, VirtualAllocEx, VirtualFreeEx, MEM_RELEASE}}, Foundation::{GetLastError, WIN32_ERROR}};

use crate::win32::Handle;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("VirtualAllocEx failed: {0:?}")]
    VirtualAllocation(WIN32_ERROR), // TODO(petra) use windows::core::Error or whatever its called

    #[error("WriteProcessMemory failed: {0:?}")]
    WriteProcessMemory(WIN32_ERROR),

    #[error(
        "Underwrote to process memory: tried to write {expected}, actually wrote {written} bytes"
    )]
    ProcessMemoryUnderwrite { expected: usize, written: usize },
}

pub unsafe fn valloc(
    proc: &Handle,
    base_addr: Option<*const c_void>,
    size: usize,
    alloc_type: VIRTUAL_ALLOCATION_TYPE,
    protection: PAGE_PROTECTION_FLAGS,
) -> Result<*mut c_void, Error> {
    trace!(?proc, ?base_addr, size, "allocation in external process");

    let addr = VirtualAllocEx(
        proc.raw(),
        base_addr.unwrap_or(ptr::null()),
        size,
        alloc_type,
        protection,
    );

    if addr.is_null() {
        Err(Error::VirtualAllocation(GetLastError()))
    } else {
        Ok(addr)
    }
}

pub unsafe fn vfree(proc: &Handle, buf: *mut c_void) {
    trace!(?proc, "freeing in external process");
    VirtualFreeEx(proc.raw(), buf, 0, MEM_RELEASE);
}

pub unsafe fn write_proc_mem(
    proc: &Handle,
    src: *const c_void,
    dst: *const c_void,
    size: usize,
) -> Result<(), Error> {
    trace!(
        ?proc,
        ?src,
        ?dst,
        size,
        "WriteProcessMemory() : {:#x} -> {:#x} ({:#x} bytes)",
        src as usize,
        dst as usize,
        size
    );

    let mut nwritten: usize = 0;
    if !WriteProcessMemory(proc.raw(), dst, src, size, &mut nwritten as _).as_bool() {
        return Err(Error::WriteProcessMemory(GetLastError()));
    }

    if size != nwritten {
        return Err(Error::ProcessMemoryUnderwrite {
            expected: size,
            written: nwritten,
        });
    }

    Ok(())
}
