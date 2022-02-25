use color_eyre::eyre::{eyre, Result};
use exe::{FileCharacteristics, PEImage, CCharString};
use std::{ffi::c_void, path::PathBuf, ptr};
use structopt::StructOpt;
use tracing::{debug, info, trace};
use windows::Win32::{
    System::{
        Memory::{
            VirtualProtectEx, MEM_COMMIT, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS, CreateRemoteThread}, LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};

use crate::{win32::Handle, mem::{valloc, write_proc_mem}};

mod redsus;
mod win32;
mod mem;

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

    #[error("GetModuleHandle() failed: {0}")]
    GetModuleHandle(windows::core::Error),

    #[error("GetProcAddress() returned nullptr")]
    GetProcAddress,
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

    // TODO(petra)
    win32::escalate();

    let pid = opt.pid;
    let host_proc: Handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }
        .ok()
        .map_err(Error::ProcOpen)?
        .into();

    debug!(pid, ?host_proc, "got proc handle for host");

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

    info!("copying PE header");
    unsafe {
        write_proc_mem(
            &host_proc,
            dll.as_ptr() as _,
            inj_img_buf,
            0x1000,
        )
    }?;

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
            )
        }?;
    }

    let hk32 = unsafe { GetModuleHandleA("kernel32.dll") }
        .ok()
        .map_err(Error::GetModuleHandle)?;
    let proc_loadliba =
        unsafe { GetProcAddress(hk32, "LoadLibraryA") }.ok_or(Error::GetProcAddress)?;
    let proc_getprocaddr =
        unsafe { GetProcAddress(hk32, "GetProcAddress") }.ok_or(Error::GetProcAddress)?;

    debug!(
        LoadLibraryA=?(proc_loadliba as *const c_void),
        GetProcAddress=?(proc_getprocaddr as *const c_void),
        "fetched kernel32.dll function pointers"
    );

    let shellcode = include_bytes!(concat!(env!("OUT_DIR"), "/redsus/redsus.bin"));
    let shellcode_buf = unsafe { valloc(
        &host_proc,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    ) }?;

    let shellcode_params_buf = unsafe { valloc(
        &host_proc,
        None,
        core::mem::size_of::<redsus::iface::ShellcodeInput>(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ) }?;

    let shellcode_params = redsus::iface::ShellcodeInput {
        base: inj_img_buf as _,
        load_library: proc_loadliba as _,
        get_proc_addr: proc_getprocaddr as _,
    };

    unsafe { write_proc_mem(
        &host_proc,
        shellcode.as_ptr() as _,
        shellcode_buf, 
        shellcode.len()
    ) }?;

    unsafe { write_proc_mem(
        &host_proc,
        &shellcode_params as *const redsus::iface::ShellcodeInput as *const c_void,
        shellcode_params_buf, 
        core::mem::size_of::<redsus::iface::ShellcodeInput>()
    ) }?;

    let h_thread = unsafe { CreateRemoteThread(
        host_proc.raw(),
        0 as _,
        0, // stack
        Some(core::mem::transmute(shellcode_buf)),
        shellcode_params_buf as _,
        0,
        0 as _,
    ) }; 

    Ok(())
}
