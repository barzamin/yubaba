mod shellcode;

use color_eyre::eyre::{eyre, Result};
use exe::{FileCharacteristics, PEImage, CCharString};
use std::{ffi::c_void, path::PathBuf, ptr};
use structopt::StructOpt;
use tracing::{debug, info, trace};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, WIN32_ERROR},
    Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{
            VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE,
        },
        SystemServices::SE_DEBUG_NAME,
        Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS, CreateRemoteThread},
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

    #[error("Couldn't open process: {0}")]
    ProcOpen(windows::core::Error),

    #[error("Error reading PE: {0}")]
    PeRead(std::io::Error),

    #[error("Error getting NT headers from PE: {0}")]
    PeNtHeaders(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("Error getting reloc directory from PE: {0}")]
    PeRelocDir(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("Error getting import directory from PE: {0}")]
    PeImportDir(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("Error relocating PE image: {0}")]
    PeReloc(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("Error parsing PE section table: {0}")]
    PeSectionTbl(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("Error reading PE section: {0}")]
    PeSectionRead(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("Shellcode generation error: {0}")]
    Shellcode(#[from] shellcode::Error),
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

unsafe fn vfree(proc: &Handle, buf: *mut c_void) {
    trace!(?proc, "freeing in external process");
    VirtualFreeEx(proc.raw(), buf, 0, MEM_RELEASE);
}

unsafe fn write_proc_mem(
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

fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();
    let opt = Opt::from_args();

    let dll = PEImage::from_disk_file(opt.dll).map_err(Error::PeRead)?;
    let nt_headers = dll
        .pe
        .get_valid_nt_headers_32()
        .map_err(|e| Error::PeNtHeaders(eyre!("{}", e)))?;

    if !nt_headers
        .file_header
        .characteristics
        .contains(FileCharacteristics::DLL)
    {
        return Err(eyre!("lib isn't a dll"));
    }

    let mut our_proc_tok: HANDLE = Default::default();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut our_proc_tok as _,
        )
    }
    .as_bool()
    {
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Attributes: SE_PRIVILEGE_ENABLED,
                ..Default::default()
            }],
        };

        if unsafe {
            LookupPrivilegeValueA(None, SE_DEBUG_NAME, &mut privileges.Privileges[0].Luid).as_bool()
        } {
            trace!("AdjustTokenPrivileges()");
            unsafe {
                AdjustTokenPrivileges(
                    &our_proc_tok,
                    false,
                    &mut privileges,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
            }
        }

        unsafe {
            CloseHandle(our_proc_tok);
        }
    }

    let pid = opt.pid;
    let host_proc: Handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }
        .ok()
        .map_err(Error::ProcOpen)?
        .into();

    debug!(pid, ?host_proc, "got proc handle for host");
/* 
    let img_size = nt_headers.optional_header.size_of_image as usize;
    let inj_img_buf = unsafe {
        valloc(
            &host_proc,
            None, //Some(pe_opt_hdr.windows_fields.image_base as *const c_void),
            img_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    }?;
    debug!(
        pid,
        size = img_size,
        addr = ?inj_img_buf,
        "allocated memory block in process"
    );

    let mut old_prot: PAGE_PROTECTION_FLAGS = Default::default();
    unsafe {
        VirtualProtectEx(
            host_proc.raw(),
            inj_img_buf as _,
            img_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot as _,
        );
    }
    debug!(?old_prot, "reprotected as R/W/X");

    let relocation_dir =
        exe::RelocationDirectory::parse(&dll.pe).map_err(|e| Error::PeRelocDir(eyre!("{}", e)))?;

    let mut relocated_dll = dll.clone();
    relocation_dir
        .relocate(&mut relocated_dll.pe, inj_img_buf as u64)
        .map_err(|e| Error::PeReloc(eyre!("{}", e)))?;

    info!("copying DLL sections");
    let section_tbl = relocated_dll
        .pe
        .get_section_table()
        .map_err(|e| Error::PeSectionTbl(eyre!("{}", e)))?;
    for section in section_tbl {
        debug!(
            "copying section {} ({} raw bytes)",
            section.name.as_str(),
            section.size_of_raw_data
        );
        if section.size_of_raw_data == 0 {
            trace!("skipping section b/c it's zero-size");
            continue;
        }

        let data = section
            .read(&relocated_dll.pe)
            .map_err(|e| Error::PeSectionRead(eyre!("{}", e)))?;
        unsafe {
            write_proc_mem(
                &host_proc,
                data.as_ptr() as *const c_void,
                inj_img_buf.add(section.virtual_address.0 as usize),
                data.len(),
            )?;
        }
    } */


    let shellcode = shellcode::load_imports(&dll.pe)?;
    println!("{:?}", shellcode);

    // let shellcode_buf = unsafe { valloc(
    //     &host_proc,
    //     None,
    //     0x100,
    //     MEM_COMMIT | MEM_RESERVE,
    //     PAGE_EXECUTE_READWRITE
    // ) }?;

    // unsafe { write_proc_mem(
    //     &host_proc,
    //     shellcode.as_ptr() as _,
    //     shellcode_buf, 
    //     shellcode.len()
    // ) }?;

    // let h_thread = unsafe { CreateRemoteThread(
    //     host_proc.raw(),
    //     0 as _,
    //     0, // stack
    //     Some(core::mem::transmute(shellcode_buf)),
    //     0 as _,
    //     0,
    //     0 as _,
    // ) }; 

    Ok(())
}
