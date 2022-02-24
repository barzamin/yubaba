use std::ffi::c_void;

use color_eyre::eyre::eyre;
use exe::{ImportDirectory, PE, CCharString, Thunk, ThunkData, ImageImportByName, ThunkFunctions};
use iced_x86::{code_asm::{ptr, AsmMemoryOperand, CodeAssembler, CodeLabel, IcedError, edi, esi, ebp, esp, dword_ptr, eax, ebx, ecx}, NasmFormatter, Formatter};
use tracing::debug;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use crate::Handle;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error getting import directory from PE: {0}")]
    PeImportDir(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("Error getting section data from PE: {0}")]
    PeSection(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("couldn't create assembler: {0}")]
    AssemblerCreation(IcedError),

    #[error("couldn't assemble shellcode: {0}")]
    AssemblyError(IcedError),

    #[error("assembly construction error: {0}")]
    AssemblyConstruct(#[from] IcedError),

    #[error("GetModuleHandle() failed: {0}")]
    GetModuleHandle(windows::core::Error),

    #[error("GetProcAddress() returned nullptr")]
    GetProcAddress,

    #[error("couldn't get thunk: {0}")]
    GetThunk(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("found a 64-bit thunk")]
    Thunk64Found,

    #[error("unable to parse named import: {0}")]
    NamedImport(color_eyre::eyre::Report), // TODO(petra): hack

    #[error("unexpected data in ILT")]
    CorruptILT,
}

struct StringTable<'a> {
    table: Vec<(CodeLabel, &'a str)>,
}

impl<'a> StringTable<'a> {
    pub fn new() -> Self {
        Self { table: vec![] }
    }

    /// Return a RIP-relative memory reference to a string, resolved at assembly time.
    pub fn add(&mut self, asm: &mut CodeAssembler, string: &'a str) -> AsmMemoryOperand {
        let label = asm.create_label();
        self.table.push((label, string));
        ptr(label)
    }

    /// Dump the string table to the current assembler position, and set labels up properly.
    pub fn writeout(self, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        for (mut label, string) in self.table {
            asm.set_label(&mut label)?;
            asm.db(string.as_bytes())?;
            asm.db(&[0])?; // null-terminated "cstr"s. kinda eww?
        }

        Ok(())
    }
}

pub fn load_imports(pe: &'_ PE) -> Result<Vec<u8>, Error> {
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

    let mut a = CodeAssembler::new(32).map_err(Error::AssemblerCreation)?;
    let mut stringtab = StringTable::new();

    // points at function return
    let mut lbl_return = a.create_label();

    // TODO(petra)
    a.int3()?;

    // -- set up our stack
    a.mov(ebp, esp)?; // enter frame
    // align frame to 4 bytes
    a.sub(esp, 0x4i32)?;
    a.and(esp, -0x4i32)?;

    // stick the necessary kernel32 function pointers in registers
    let reg_loadliba = esi;
    let reg_getprocaddr = edi;
    a.mov(reg_loadliba, proc_loadliba as u32)?;
    a.mov(reg_getprocaddr, proc_loadliba as u32)?;

    let import_dir = ImportDirectory::parse(pe).map_err(|e| Error::PeImportDir(eyre!("{}", e)))?;

    // generate LoadLibrary calls and code to write out IAT thunks
    for import in import_dir.descriptors {
        let name = import.get_name(pe).map_err(|e| Error::PeSection(eyre!("{}", e)))?.as_str();
        debug!(?import, name, "processing import {}", name);

        // PUSH {addr of DLL name}
        let str_dllname = stringtab.add(&mut a, name);
        debug!("{:?}", str_dllname);
        a.lea(ecx, str_dllname)?; // TODO?
        a.push(ecx)?;
        a.call(reg_loadliba)?; // LoadLibA(name)

        // did load work successfully?
        a.test(eax, eax)?;
        let mut lbl_succ = a.create_label();
        // if retn != 0, jump over {eax <- 1, jump(retn)}
        a.jnz(lbl_succ)?;
        // failmale
        a.inc(eax)?; // eax was 0. make it 1; we're returning 1 on failure.
        a.jmp(lbl_return)?;

        a.set_label(&mut lbl_succ)?; // label so we can jump over the above.

        let reg_module_handle = ebx;
        a.mov(reg_module_handle, eax)?; // ebx <- retn of LoadLibraryA (HMODULE).

        for thunk in import.get_lookup_thunks(pe).map_err(|e| Error::GetThunk(eyre!("{}", e)))? {
            let thunk = match thunk {
                Thunk::Thunk32(x) => Ok(x),
                _ => Err(Error::Thunk64Found),
            }?;

            let fn_ptr = match thunk.parse_import() {
                ThunkData::Ordinal(o) => {
                    assert!(o <= 0xffff); // "if this parameter is an ordinal, it must be in the low-order word" - msdn, GetProcAddress
                    
                    Ok(ptr(o))
                },
                ThunkData::ImportByName(rva) => {
                    let import_by_name = ImageImportByName::parse(pe, rva).map_err(|e| Error::NamedImport(eyre!("{}", e)))?;
                    
                    Ok(stringtab.add(&mut a, import_by_name.name.as_str()))
                }
                _ => Err(Error::CorruptILT),
            }?;
        }
    }

    a.xor(eax, eax)?; // retn 0 if successful
    a.set_label(&mut lbl_return)?;
    a.mov(esp, ebp)?; // restore caller frame
    a.ret()?;

    // dump all the strings we need as .db
    stringtab.writeout(&mut a)?;

    // debug!("asm: {:#?}", a.instructions());
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);
    for instruction in a.instructions() {
        let mut output = String::new();
        formatter.format(instruction, &mut output);
        println!("{:016X}  {}", instruction.ip(), output);
    }

    a.assemble(0).map_err(Error::AssemblyError) // all PIC :)
}
