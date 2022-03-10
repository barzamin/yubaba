use std::{
    collections::{hash_map::Entry, HashMap},
    ptr,
};

use egui::{plot::Text, text, TextureId};
use windows::Win32::Graphics::Direct3D9::{
    IDirect3D9, IDirect3DDevice9, IDirect3DTexture9, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT,
    D3DUSAGE_DYNAMIC,
};

use crate::Error;

pub(crate) struct Texture {
    size: [usize; 2],
    inner: IDirect3DTexture9,
}

impl Texture {
    pub unsafe fn create(device: &IDirect3DDevice9, size: [usize; 2]) -> Result<Self, Error> {
        let mut tex: Option<IDirect3DTexture9> = None;
        device.CreateTexture(
            size[0] as u32,
            size[1] as u32,
            1,                       // #miplevels
            D3DUSAGE_DYNAMIC as u32, // we might delta-update
            D3DFMT_A8R8G8B8,         // TODO(petra) lol hardcoded
            D3DPOOL_DEFAULT,
            &mut tex,
            ptr::null_mut(),
        )?;

        Ok(Self {
            inner: tex.ok_or_else(|| Error::CreatedNullTexture)?,
            size,
        })
    }

    pub fn raw(&self) -> &IDirect3DTexture9 {
        &self.inner
    }
}

pub(crate) struct Textures {
    textures: HashMap<TextureId, Texture>,
}

impl Textures {
    pub fn new() -> Self {
        Self {
            textures: HashMap::new(),
        }
    }

    pub fn insert(&mut self, texture_id: TextureId, texture: Texture) -> Option<Texture> {
        self.textures.insert(texture_id, texture)
    }

    pub fn free(&mut self, texture_id: TextureId) -> Result<(), Error> {
        let texture = self
            .textures
            .remove(&texture_id)
            .ok_or_else(|| Error::NoSuchTexture(texture_id))?;
        drop(texture);

        Ok(())
    }

    pub fn get(&self, texture_id: TextureId) -> Result<&Texture, Error> {
        self.textures
            .get(&texture_id)
            .ok_or_else(|| Error::NoSuchTexture(texture_id))
    }
}
