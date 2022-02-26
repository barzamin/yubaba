use std::ptr;

use tracing::trace;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::{
        SystemServices::SE_DEBUG_NAME,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

/// [`HANDLE`] wrapper that calls [`CloseHandle`] on [`Drop`].
#[derive(Debug)]
pub struct Handle(pub HANDLE);

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

// TODO(petra): bad bad bad bad
pub fn escalate() {
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
}
