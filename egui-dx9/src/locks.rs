use std::ops::{Deref, DerefMut};

use windows::Win32::Graphics::Direct3D9::{IDirect3DIndexBuffer9, IDirect3DVertexBuffer9};

pub(crate) trait DxUnlockable {
    unsafe fn unlock(&self) -> Result<(), windows::core::Error>;
}

macro_rules! dx_unlockable {
    ($ty:ident) => {
        impl DxUnlockable for $ty {
            unsafe fn unlock(&self) -> Result<(), windows::core::Error> {
                self.Unlock()
            }
        }
    };
}

dx_unlockable!(IDirect3DVertexBuffer9);
dx_unlockable!(IDirect3DIndexBuffer9);

pub(crate) struct DxLockGuard<'a, B, T>
where
    B: DxUnlockable,
{
    data: T,
    owner: &'a B,
}

impl<'a, B, T> DxLockGuard<'a, B, T>
where
    B: DxUnlockable,
{
    pub fn new(owner: &'a B, data: T) -> Self {
        Self { data, owner }
    }
}

impl<'a, B, T> Deref for DxLockGuard<'a, B, T>
where
    B: DxUnlockable,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<'a, B, T> DerefMut for DxLockGuard<'a, B, T>
where
    B: DxUnlockable,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<'a, B, T> Drop for DxLockGuard<'a, B, T>
where
    B: DxUnlockable,
{
    fn drop(&mut self) {
        unsafe { self.owner.unlock() }.unwrap(); // panic on failed drop lock release. lol basically Poisoning For Dx
    }
}
