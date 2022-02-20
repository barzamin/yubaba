use color_eyre::eyre::{eyre, Result};
use goblin::pe::{self, PE};
use std::{ffi::c_void, path::PathBuf, ptr};
use structopt::StructOpt;
use tracing::{debug, trace};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, WIN32_ERROR},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{
            VirtualAllocEx, MEM_RESERVE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
            VIRTUAL_ALLOCATION_TYPE, PAGE_EXECUTE_READWRITE,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

#[derive(Debug, StructOpt)]
struct Opt {
    pid: u32,

    #[structopt(parse(from_os_str))]
    dll: PathBuf,

    /// dry dry bones
    #[structopt(short, long)]
    dry: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("VirtualAllocEx failed: {0:?}")]
    VirtualAllocation(WIN32_ERROR),

    #[error("WriteProcessMemory failed: {0:?}")]
    WriteProcessMemory(WIN32_ERROR),

    #[error(
        "Underwrote to process memory: tried to write {expected}, actually wrote {written} bytes"
    )]
    ProcessMemoryUnderwrite { expected: usize, written: usize },
}

/// [`HANDLE`] wrapper that calls [`CloseHandle`] on [`Drop`].
#[derive(Debug)]
struct Handle(pub HANDLE);

impl Handle {
    pub fn new(h: HANDLE) -> Self {
        Self(h)
    }

    pub unsafe fn raw(&self) -> HANDLE {
        self.0
    }
}

impl From<HANDLE> for Handle {
    fn from(h: HANDLE) -> Self {
        Handle::new(h)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        trace!("dropping handle {:?}", self.0);
        unsafe { CloseHandle(self.0) }
            .ok()
            .expect("failed to CloseHandle()")
    }
}

unsafe fn valloc(
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

unsafe fn write_proc_mem(
    proc: &Handle,
    src: *const c_void,
    dst: *const c_void,
    size: usize,
) -> Result<(), Error> {
    let mut nwritten: usize = 0;
    if !WriteProcessMemory(proc.raw(), src, dst, size, &mut nwritten as _).as_bool() {
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

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();
    let opt = Opt::from_args();

    let dll_buf = std::fs::read(opt.dll)?;
    let pe = PE::parse(&dll_buf)?;

    if !pe.is_lib {
        return Err(eyre!("lib isn't a dll"));
    }

    if pe.is_64 {
        // TODO!
        return Err(eyre!(
            "(assuming!) host is 32bit/Wow64. can't inject 64-bit DLL"
        ));
    }

    let pe_opt_hdr = pe
        .header
        .optional_header
        .ok_or_else(|| eyre!("DLL missing optional header"))?;
    let img_size = pe_opt_hdr.windows_fields.size_of_image as usize;

    let pid = opt.pid;
    let host_proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }
        .ok()?
        .into();

    debug!(pid, ?host_proc, "got proc handle for host");
    debug!(img_base=pe_opt_hdr.windows_fields.image_base, "dll image base?");

    let inj_img_buf = unsafe {
        valloc(
            &host_proc,
            None, //Some(pe_opt_hdr.windows_fields.image_base as *const c_void),
            img_size,
            MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }?;
    debug!(pid, size = img_size, "allocated memory block in process");

    for section in pe.sections {
        debug!(?section, name=%String::from_utf8_lossy(&section.name).into_owned(), "pe section");
    }

    Ok(())
}
