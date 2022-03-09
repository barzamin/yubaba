use std::{
    mem,
    ops::{Deref, DerefMut, Range},
    ptr, slice,
};

use windows::Win32::{
    Graphics::Direct3D9::{
        IDirect3DDevice9, IDirect3DIndexBuffer9, IDirect3DVertexBuffer9, D3DFMT_INDEX32,
        D3DLOCK_DISCARD, D3DPOOL_DEFAULT, D3DUSAGE_DYNAMIC, D3DUSAGE_WRITEONLY,
    },
    System::SystemServices::{D3DFVF_DIFFUSE, D3DFVF_TEX1, D3DFVF_XYZ},
};

use crate::{
    locks::{DxLockGuard, DxUnlockable},
    Error,
};

// TODO(petra) kinda hacky lol
pub(crate) const D3DFVF_CUSTOMVERTEX: u32 = D3DFVF_XYZ | D3DFVF_DIFFUSE | D3DFVF_TEX1;

#[repr(C)]
pub(crate) struct CustomVertex {
    pub pos: [f32; 3],
    pub col: [u8; 4],
    pub uv: [f32; 2],
}

pub(crate) trait DxBuffer: Sized {
    type RawBuffer: DxUnlockable;
    type Element;

    fn allocate(device: &IDirect3DDevice9, max_size: usize) -> Result<Self, Error>;
    fn size(&self) -> usize;

    fn raw(&self) -> &Self::RawBuffer;
    fn raw_mut(&mut self) -> &mut Self::RawBuffer;

    fn lock(
        &mut self,
        range: Range<usize>,
    ) -> Result<DxLockGuard<Self::RawBuffer, &mut [Self::Element]>, Error>;
}

pub(crate) struct Resizing<T>
where
    T: DxBuffer,
{
    backing: T,
}

impl<T> Resizing<T>
where
    T: DxBuffer,
{
    pub fn with_capacity(device: &IDirect3DDevice9, capacity: usize) -> Result<Self, Error> {
        Ok(Self {
            backing: T::allocate(device, capacity)?,
        })
    }

    pub fn lock(
        &mut self,
        device: &IDirect3DDevice9,
        range: Range<usize>,
    ) -> Result<DxLockGuard<T::RawBuffer, &mut [T::Element]>, Error> {
        if range.len() > self.backing.size() {
            // need to grow
            // self.backing.
            drop(mem::replace(
                &mut self.backing,
                T::allocate(device, range.len() * 2)?, // double requested size
            ));
        }

        self.backing.lock(range)
    }

    pub fn raw(&self) -> &T::RawBuffer {
        self.backing.raw()
    }

    pub fn raw_mut(&mut self) -> &mut T::RawBuffer {
        self.backing.raw_mut()
    }
}

pub(crate) struct VertexBuffer {
    size: usize,
    buffer: IDirect3DVertexBuffer9,
}

impl VertexBuffer {
    unsafe fn create_vtx_buf(
        device: &IDirect3DDevice9,
        vtx_count: usize,
    ) -> Result<IDirect3DVertexBuffer9, Error> {
        let mut vtx_buf: Option<IDirect3DVertexBuffer9> = None;
        device.CreateVertexBuffer(
            (vtx_count * mem::size_of::<CustomVertex>()) as u32,
            mem::transmute(D3DUSAGE_DYNAMIC | D3DUSAGE_WRITEONLY),
            D3DFVF_CUSTOMVERTEX,
            D3DPOOL_DEFAULT,
            &mut vtx_buf,
            ptr::null_mut(),
        )?;

        vtx_buf.ok_or(Error::MissingVtxBuf)
    }
}

impl DxBuffer for VertexBuffer {
    type RawBuffer = IDirect3DVertexBuffer9;
    type Element = CustomVertex;

    fn size(&self) -> usize {
        self.size
    }

    fn allocate(device: &IDirect3DDevice9, max_size: usize) -> Result<Self, Error> {
        Ok(Self {
            buffer: unsafe { Self::create_vtx_buf(device, max_size) }?,
            size: max_size,
        })
    }

    fn raw(&self) -> &Self::RawBuffer {
        &self.buffer
    }

    fn raw_mut(&mut self) -> &mut Self::RawBuffer {
        &mut self.buffer
    }

    fn lock(
        &mut self,
        range: Range<usize>,
    ) -> Result<DxLockGuard<Self::RawBuffer, &mut [Self::Element]>, Error> {
        let mut lock_dst: *mut Self::Element = ptr::null_mut();
        unsafe {
            self.buffer.Lock(
                range.start as u32,
                range.len() as u32,
                &mut lock_dst as *mut _ as _,
                D3DLOCK_DISCARD as u32, // TODO(petra) can we do more efficient buffer management?
            )
        }?;

        Ok(DxLockGuard::new(
            &self.buffer,
            unsafe { slice::from_raw_parts_mut(lock_dst, range.len()) }, // TODO(petra) this is unsound
        ))
    }
}

pub(crate) struct IndexBuffer {
    size: usize,
    buffer: IDirect3DIndexBuffer9,
}

impl IndexBuffer {
    unsafe fn create_idx_buf(
        device: &IDirect3DDevice9,
        idx_count: usize,
    ) -> Result<IDirect3DIndexBuffer9, Error> {
        let mut idx_buf: Option<IDirect3DIndexBuffer9> = None;
        device.CreateIndexBuffer(
            (idx_count * mem::size_of::<u32>()) as u32,
            mem::transmute(D3DUSAGE_DYNAMIC | D3DUSAGE_WRITEONLY),
            D3DFMT_INDEX32,
            D3DPOOL_DEFAULT,
            &mut idx_buf,
            ptr::null_mut(),
        )?;

        idx_buf.ok_or(Error::MissingIdxBuf)
    }
}

impl DxBuffer for IndexBuffer {
    type RawBuffer = IDirect3DIndexBuffer9;
    type Element = u32;

    fn size(&self) -> usize {
        self.size
    }

    fn allocate(device: &IDirect3DDevice9, max_size: usize) -> Result<Self, Error> {
        Ok(Self {
            buffer: unsafe { Self::create_idx_buf(device, max_size) }?,
            size: max_size,
        })
    }

    fn raw(&self) -> &Self::RawBuffer {
        &self.buffer
    }

    fn raw_mut(&mut self) -> &mut Self::RawBuffer {
        &mut self.buffer
    }

    fn lock(
        &mut self,
        range: Range<usize>,
    ) -> Result<DxLockGuard<Self::RawBuffer, &mut [Self::Element]>, Error> {
        let mut lock_dst: *mut Self::Element = ptr::null_mut();
        unsafe {
            self.buffer.Lock(
                range.start as u32,
                range.len() as u32,
                &mut lock_dst as *mut _ as _,
                D3DLOCK_DISCARD as u32, // TODO(petra) can we do more efficient buffer management?
            )
        }?;

        Ok(DxLockGuard::new(
            &self.buffer,
            unsafe { slice::from_raw_parts_mut(lock_dst, range.len()) }, // TODO(petra) this is unsound
        ))
    }
}
