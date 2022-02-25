use super::win32;

#[repr(C)]
pub struct ShellcodeInput {
    pub base: *const win32::c_void,
    pub load_library: *const win32::LoadLibraryA,
    pub get_proc_addr: *const win32::GetProcAddress,
}
