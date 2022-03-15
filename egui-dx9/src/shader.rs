use tracing::trace;
use windows::Win32::Graphics::Direct3D9::{
    IDirect3DDevice9, IDirect3DPixelShader9, IDirect3DVertexShader9,
};

pub trait Shader: Sized {
    unsafe fn create(
        device: &IDirect3DDevice9,
        binary: *const u32,
    ) -> Result<Self, windows::core::Error>;
}

impl Shader for IDirect3DPixelShader9 {
    unsafe fn create(
        device: &IDirect3DDevice9,
        binary: *const u32,
    ) -> Result<Self, windows::core::Error> {
        trace!("creating pixel shader from blob");
        device.CreatePixelShader(binary)
    }
}

impl Shader for IDirect3DVertexShader9 {
    unsafe fn create(
        device: &IDirect3DDevice9,
        binary: *const u32,
    ) -> Result<Self, windows::core::Error> {
        trace!("creating vertex shader from blob");
        device.CreateVertexShader(binary)
    }
}
