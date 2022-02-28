use color_eyre::eyre::{eyre, Result};
use core::mem;
use exe::{CCharString, FileCharacteristics, PEImage, PEType, PE};
use std::{ffi::c_void, path::PathBuf, ptr};
use structopt::StructOpt;
use tracing::{debug, info, trace};
use windows::Win32::System::{
    LibraryLoader::{GetModuleHandleA, GetProcAddress},
    Memory::{
        VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
        PAGE_READWRITE,
    },
    Threading::{CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS},
};

use crate::{
    memory::{valloc, write_proc_mem},
    win32::Handle,
};

mod memory;
mod win32;

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
            None,
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
    unsafe { write_proc_mem(&host_proc, dll.as_ptr() as _, inj_img_buf, 0x1000) }?;

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

    let shellcode_pe = PE {
        pe_type: PEType::Disk,
        buffer: exe::Buffer::new(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/redsus/redsus.exe"
        ))),
    };
    let shellcode_nt_headers = shellcode_pe
        .get_valid_nt_headers_32()
        .map_err(|e| eyre!("{}", e))?;
    let shellcode_text_section = shellcode_pe
        .get_section_by_name(".text".to_string())
        .map_err(|e| eyre!("{}", e))?;
    let shellcode_text = shellcode_text_section
        .read(&shellcode_pe)
        .map_err(|e| eyre!("{}", e))?;

    let shellcode_buf = unsafe {
        valloc(
            &host_proc,
            None,
            shellcode_text.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }?;

    unsafe {
        write_proc_mem(
            &host_proc,
            shellcode_text.as_ptr() as _,
            shellcode_buf,
            shellcode_text.len(),
        )
    }?;

    debug!(
        "shellcode entry point {:#x}",
        shellcode_nt_headers
            .optional_header
            .address_of_entry_point
            .0
    );
    let entry_pt_offset = (shellcode_nt_headers
        .optional_header
        .address_of_entry_point
        .0
        - shellcode_text_section.virtual_address.0) as isize;
    let shellcode_entry_pt =
        unsafe { mem::transmute((shellcode_buf as *const u8).offset(entry_pt_offset)) };
    debug!(
        "entry point offset: {:#x}, entering at: {:?}",
        entry_pt_offset, shellcode_entry_pt as *const c_void
    );
    let h_thread = unsafe {
        CreateRemoteThread(
            host_proc.raw(),
            0 as _,
            0, // stack
            Some(shellcode_entry_pt),
            inj_img_buf as _,
            0,
            0 as _,
        )
    };

    Ok(())
}
