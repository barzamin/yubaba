#![allow(bad_style, dead_code)]

pub enum c_void {}
pub type c_char = i8;
pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_short = i16;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_long = i32;
pub type c_ulong = u32;
pub type c_longlong = i64;
pub type c_ulonglong = u64;
pub type c_float = f32;
pub type c_double = f64;
pub type __int8 = i8;
pub type __uint8 = u8;
pub type __int16 = i16;
pub type __uint16 = u16;
pub type __int32 = i32;
pub type __uint32 = u32;
pub type __int64 = i64;
pub type __uint64 = u64;
pub type wchar_t = u16;
pub type CHAR = c_char;
pub type BYTE = c_uchar;
pub type WORD = c_ushort;
pub type LONG = c_long;
pub type DWORD = c_ulong;
pub type ULONG_PTR = usize;
pub type LPCSTR = *const CHAR;
pub type BOOL = c_int;
pub type BOOLEAN = BYTE;
pub type WCHAR = wchar_t;
pub type PWCH = *mut WCHAR;
pub type PVOID = *mut c_void;
pub type USHORT = c_ushort;
pub type ULONG = c_ulong;
pub type HANDLE = *mut c_void;
pub enum HINSTANCE__ {}
pub type HINSTANCE = *mut HINSTANCE__;
pub type HMODULE = HINSTANCE;
pub type LPVOID = *mut c_void;
pub type LoadLibraryA = unsafe extern "stdcall" fn(LPCSTR) -> HMODULE;
pub type GetProcAddress = unsafe extern "stdcall" fn(HMODULE, LPCSTR) -> LPVOID;

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub BaseOfData: DWORD,
    pub ImageBase: DWORD,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: DWORD,
    pub SizeOfStackCommit: DWORD,
    pub SizeOfHeapReserve: DWORD,
    pub SizeOfHeapCommit: DWORD,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: WORD = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: WORD = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: WORD = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: WORD = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: WORD = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: WORD = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: WORD = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: WORD = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: WORD = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: WORD = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: WORD = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: WORD = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: WORD = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: WORD = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: WORD = 14;

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub OriginalFirstThunk: DWORD,
    pub TimeDateStamp: DWORD,
    pub ForwarderChain: DWORD,
    pub Name: DWORD,
    pub FirstThunk: DWORD,
}

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: WORD,
    pub Name: [CHAR; 1],
}

pub const DLL_PROCESS_ATTACH: DWORD = 1;

#[repr(C)]
pub struct PEB {
  pub InheritedAddressSpace: BOOLEAN,
  pub ReadImageFileExecOptions: BOOLEAN,
  pub BeingDebugged: BOOLEAN,
  pub BitField: BOOLEAN,
  pub Mutant: HANDLE,
  pub ImageBaseAddress: PVOID,
  pub Ldr: *mut PEB_LDR_DATA,
  pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,

  // ...
}

// via undocumented.ntinternals.net
#[repr(C)]
pub struct PEB_LDR_DATA {
  pub Length: ULONG,
  pub Initialized: BOOLEAN,
  pub SsHandle: HANDLE,
  pub InLoadOrderModuleList: LIST_ENTRY,
  pub InMemoryOrderModuleList: LIST_ENTRY,
  pub InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}


#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWCH,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LIST_ENTRY,
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    // ...
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
  pub MaximumLength: ULONG,
  pub Length: ULONG,
  pub Flags: ULONG,
  pub DebugFlags: ULONG,
  pub ConsoleHandle: HANDLE,
  pub ConsoleFlags: ULONG,
  pub StandardInput: HANDLE,
  pub StandardOutput: HANDLE,
  pub StandardError: HANDLE,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}