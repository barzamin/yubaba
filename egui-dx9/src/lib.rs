use std::{collections::HashMap, mem, ptr};

use buffer::CustomVertex;
use egui::{epaint::ClippedShape, ClippedMesh, TextureId};
use windows::Win32::{
    Foundation::RECT,
    Graphics::Direct3D9::{
        IDirect3DBaseTexture9, IDirect3DDevice9, IDirect3DIndexBuffer9, IDirect3DVertexBuffer9,
        D3DCULL_NONE, D3DPT_TRIANGLELIST, D3DRS_CULLMODE, D3DVIEWPORT9,
    },
};

mod buffer;
mod locks;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("win32 api error: {0}")]
    Win32Error(#[from] windows::core::Error),

    #[error("CreateVertexBuffer returned no buffer")]
    MissingVtxBuf,

    #[error("CreateIndexBuffer returned no buffer")]
    MissingIdxBuf,

    #[error("attempted to remove texture id {0:?} which does not exist")]
    NoSuchTexture(TextureId),
}

pub struct EguiDx9<'a> {
    egui_ctx: egui::Context,
    d3ddevice: &'a IDirect3DDevice9,

    shapes: Vec<ClippedShape>,
    textures_delta: egui::TexturesDelta,

    textures: Textures,
}

struct Textures {
    textures: HashMap<TextureId, IDirect3DBaseTexture9>,
}

impl Textures {
    fn new() -> Self {
        Self {
            textures: Default::default(),
        }
    }

    // fn insert(&mut self, texture_id: u32, )

    fn free(&mut self, texture_id: TextureId) -> Result<(), Error> {
        let texture = self
            .textures
            .remove(&texture_id)
            .ok_or_else(|| Error::NoSuchTexture(texture_id))?;
        drop(texture);

        Ok(())
    }

    fn get(&self, texture_id: TextureId) -> Result<&IDirect3DBaseTexture9, Error> {
        self.textures
            .get(&texture_id)
            .ok_or_else(|| Error::NoSuchTexture(texture_id))
    }
}

struct CoalescedDraw {
    pub texture_id: TextureId,

    pub vertex_offset: usize,
    pub index_offset: usize,
    pub vertex_count: usize,
    pub tri_count: usize,

    pub scissors: RECT,
}

fn upload_geometry(
    // TODO DONT PASS LOCKED THINGS IN
    mut vb: &mut [CustomVertex],
    mut ib: &mut [u32],
    clipped_meshes: &[ClippedMesh],
) -> Result<Vec<CoalescedDraw>, Error> {
    let mut vertex_offset = 0;
    let mut index_offset = 0;
    let mut draws = Vec::new();
    for clipped_mesh in clipped_meshes {
        let ClippedMesh(scissor, shape) = clipped_mesh;

        // TODO(petra): check coordinate system
        let scissor_rect = RECT {
            left: scissor.left() as i32,
            top: scissor.top() as i32,
            right: scissor.right() as i32,
            bottom: scissor.bottom() as i32,
        };

        let vertex_count = shape.vertices.len();
        let index_count = shape.indices.len();
        let tri_count = index_count / 3;
        draws.push(CoalescedDraw {
            vertex_offset,
            index_offset,
            vertex_count,
            tri_count,
            texture_id: shape.texture_id,
            scissors: scissor_rect,
        });
        vertex_offset += vertex_count;
        index_offset += index_count;

        for (vert, dest) in shape.vertices.iter().zip(vb.iter_mut()) {
            *dest = CustomVertex {
                pos: [vert.pos.x, vert.pos.y, 0.], // z=0 for all egui meshes
                col: [
                    vert.color.a(),
                    vert.color.r(),
                    vert.color.g(),
                    vert.color.b(),
                ],
                uv: [vert.uv.x, vert.uv.y],
            };
        }
        ib[..shape.indices.len()].copy_from_slice(&shape.indices);

        // "move pointers" so we write after the last mesh we did
        vb = &mut vb[vertex_count..];
        ib = &mut ib[index_count..];
    }

    Ok(draws)
}

impl<'a> EguiDx9<'a> {
    pub fn new(device: &'a IDirect3DDevice9) -> Self {
        Self {
            egui_ctx: Default::default(),
            d3ddevice: device,

            shapes: Default::default(),
            textures_delta: Default::default(),

            textures: Textures::new(),
        }
    }

    pub fn run(&mut self, run_ui: impl FnMut(&egui::Context)) -> bool {
        let raw_input = Default::default(); // TODO(petra)
        let egui::FullOutput {
            platform_output,
            needs_repaint,
            textures_delta,
            shapes,
        } = self.egui_ctx.run(raw_input, run_ui);

        // TODO(petra) handle platform output

        self.shapes = shapes;
        self.textures_delta.append(textures_delta);

        needs_repaint
    }

    unsafe fn render_state_setup(&mut self, viewport_size: [u32; 2]) -> Result<(), Error> {
        // TODO(petra): fb size

        let vp = D3DVIEWPORT9 {
            X: 0,
            Y: 0,
            Width: viewport_size[0],
            Height: viewport_size[1],
            MinZ: 0.0,
            MaxZ: 1.0,
        };
        self.d3ddevice.SetViewport(&vp)?;
        // use fixed-function dx9 pipeline
        self.d3ddevice.SetPixelShader(None)?;
        self.d3ddevice.SetVertexShader(None)?;
        // "egui is NOT consistent with what winding order it uses, so turn off backface culling."
        self.d3ddevice
            .SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE.0)?;

        Ok(())
    }

    pub fn paint(&mut self /* , dimensions: [u32; 2] */) -> Result<(), Error> {
        let shapes = mem::take(&mut self.shapes);
        let mut textures_delta = std::mem::take(&mut self.textures_delta);

        for (id, image_delta) in textures_delta.set {
            // apply texture
            // NOTE: D3DPOOL_MANAGED
            // SEE: https://stackoverflow.com/questions/14955954/update-directx-texture
        }

        let clipped_meshes = self.egui_ctx.tessellate(shapes);

        // scan through meshes and upload merged vert/index lists so we only upload
        // a single vtx buffer and a single idx buffer.
        let draws = upload_geometry(todo!(), todo!(), todo!())?;

        let mut last_tex = None;
        for draw in draws {
            if last_tex != Some(draw.texture_id) {
                // need to switch used texture for this draw call!
                unsafe {
                    self.d3ddevice
                        .SetTexture(0, self.textures.get(draw.texture_id)?)?;
                }
                last_tex = Some(draw.texture_id);
            }

            unsafe {
                self.d3ddevice.SetScissorRect(&draw.scissors)?;
                self.d3ddevice.DrawIndexedPrimitive(
                    D3DPT_TRIANGLELIST,
                    draw.vertex_offset as i32,
                    0,
                    draw.vertex_count as u32,
                    draw.index_offset as u32,
                    draw.tri_count as u32,
                )?;
            }
        }

        for id in textures_delta.free.drain(..) {
            // free texture
            self.textures.free(id)?;
        }

        Ok(())
    }
}