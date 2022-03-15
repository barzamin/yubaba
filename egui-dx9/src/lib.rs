use core::slice;
use std::{
    borrow::Borrow,
    collections::{hash_map::Entry, HashMap},
    mem, ptr,
};

use egui::{epaint::ClippedShape, ClippedMesh, Color32, ImageData, Rgba, TextureId};
use tracing::{debug, span, trace, Level};
use windows::Win32::{
    Foundation::RECT,
    Graphics::{
        Direct3D::{D3DMATRIX, D3DMATRIX_0},
        Direct3D9::{
            IDirect3DDevice9, IDirect3DIndexBuffer9, IDirect3DPixelShader9, IDirect3DStateBlock9,
            IDirect3DVertexShader9, D3DBLENDOP_ADD, D3DBLEND_INVSRCALPHA, D3DBLEND_SRCALPHA,
            D3DCULL_NONE, D3DLOCKED_RECT, D3DPT_TRIANGLELIST, D3DRS_ALPHABLENDENABLE,
            D3DRS_ALPHATESTENABLE, D3DRS_BLENDOP, D3DRS_CULLMODE, D3DRS_DESTBLEND, D3DRS_FOGENABLE,
            D3DRS_LIGHTING, D3DRS_SCISSORTESTENABLE, D3DRS_SHADEMODE, D3DRS_SRCBLEND,
            D3DRS_ZENABLE, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSBT_ALL, D3DSHADE_GOURAUD,
            D3DTEXF_LINEAR, D3DTOP_MODULATE, D3DTRANSFORMSTATETYPE, D3DTSS_ALPHAARG1,
            D3DTSS_ALPHAARG2, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLORARG2, D3DTSS_COLOROP,
            D3DTS_PROJECTION, D3DTS_VIEW, D3DVIEWPORT9,
        },
    },
    System::SystemServices::{D3DTA_DIFFUSE, D3DTA_TEXTURE},
};

mod buffer;
mod locks;
mod shader;
mod texture;

use crate::buffer::{CustomVertex, IndexBuffer, Resizing, VertexBuffer};
use crate::shader::Shader;
use crate::texture::{Texture, Textures};

const DEFAULT_VERTEX_BUFFER_SIZE: usize = 5000;
const DEFAULT_INDEX_BUFFER_SIZE: usize = 1000 * 3;

static MAT_IDENTITY: D3DMATRIX = D3DMATRIX {
    Anonymous: D3DMATRIX_0 {
        m: [
            1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
        ],
    },
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("win32 api error: {0}")]
    Win32Error(#[from] windows::core::Error),

    #[error("CreateVertexBuffer returned no buffer")]
    MissingVtxBuf,

    #[error("CreateVertexDeclaration returned no decl")]
    MissingVtxDecl,

    #[error("CreateIndexBuffer returned no buffer")]
    MissingIdxBuf,

    #[error("attempted to remove texture id {0:?} which does not exist")]
    NoSuchTexture(TextureId),

    #[error("CreateTexture returned no texture")]
    CreatedNullTexture,
}

struct StateGuard {
    previous: IDirect3DStateBlock9,
}

impl StateGuard {
    unsafe fn backup(device: &IDirect3DDevice9) -> Result<Self, Error> {
        Ok(Self {
            previous: device.CreateStateBlock(D3DSBT_ALL)?,
        })
    }
}

impl Drop for StateGuard {
    fn drop(&mut self) {
        unsafe { self.previous.Apply() }.unwrap(); // restore old state
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

pub struct EguiDx9 {
    egui_ctx: egui::Context,

    // egui frame state
    shapes: Vec<ClippedShape>,
    textures_delta: egui::TexturesDelta,

    // owned d3d resources
    textures: Textures,
    vertex_buffer: Resizing<VertexBuffer>,
    index_buffer: Resizing<IndexBuffer>,

    vertex_shader: IDirect3DVertexShader9,
    pixel_shader: IDirect3DPixelShader9,
}

type ARGB = [u8; 4];
fn color32_to_argb(c: Color32) -> ARGB {
    [c.a(), c.r(), c.g(), c.b()]
}

impl EguiDx9 {
    pub fn new(device: &IDirect3DDevice9) -> Result<Self, Error> {
        Ok(Self {
            egui_ctx: Default::default(),

            shapes: Default::default(),
            textures_delta: Default::default(),

            textures: Textures::new(),

            vertex_buffer: Resizing::<_>::with_capacity(device, DEFAULT_VERTEX_BUFFER_SIZE)?,
            index_buffer: Resizing::<_>::with_capacity(device, DEFAULT_INDEX_BUFFER_SIZE)?,

            vertex_shader: unsafe {
                IDirect3DVertexShader9::create(
                    device,
                    include_bytes!("shader/vert.bin") as *const _ as *const u32,
                )
            }?,
            pixel_shader: unsafe {
                IDirect3DPixelShader9::create(
                    device,
                    include_bytes!("shader/pix.bin") as *const _ as *const u32,
                )
            }?,
        })
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

    unsafe fn setup_dx_state(
        &mut self,
        device: &IDirect3DDevice9,
        viewport_size: [u32; 2],
    ) -> Result<(), Error> {
        // TODO(petra): fb size

        let vp = D3DVIEWPORT9 {
            X: 0,
            Y: 0,
            Width: viewport_size[0],
            Height: viewport_size[1],
            MinZ: 0.0,
            MaxZ: 1.0,
        };
        device.SetViewport(&vp)?;
        device.SetPixelShader(&self.pixel_shader)?;
        device.SetVertexShader(&self.vertex_shader)?;
        // "egui is NOT consistent with what winding order it uses, so turn off backface culling."
        device.SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE.0)?;
        device.SetRenderState(D3DRS_LIGHTING, false.into())?;
        device.SetRenderState(D3DRS_ZENABLE, false.into())?;
        device.SetRenderState(D3DRS_ALPHABLENDENABLE, true.into())?;
        device.SetRenderState(D3DRS_ALPHATESTENABLE, false.into())?;
        device.SetRenderState(D3DRS_BLENDOP, D3DBLENDOP_ADD.0)?;
        device.SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA.0)?;
        device.SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA.0)?;
        device.SetRenderState(D3DRS_SCISSORTESTENABLE, true.into())?;
        device.SetRenderState(D3DRS_SHADEMODE, D3DSHADE_GOURAUD.0 as _)?;
        device.SetRenderState(D3DRS_FOGENABLE, false.into())?;
        // device.SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE.0 as _)?;
        // device.SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE as _)?;
        // device.SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE as _)?;
        // device.SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE.0 as _)?;
        // device.SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE as _)?;
        // device.SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE as _)?;
        device.SetSamplerState(0, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as _)?;
        device.SetSamplerState(0, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as _)?;

        // TODO(petra) BIG TODO MAKE THIS NOT 0
        // let l = 0.5;
        // let r = viewport_size[0] as f32+0.5;
        // let t = 0.5;
        // let b = viewport_size[1]as f32+0.5;
        // let mat_proj = D3DMATRIX {
        //     Anonymous: D3DMATRIX_0 {
        //         m: [
        //             2.0/(r-l), 0.0, 0.0, 0.0, //
        //             0.0, 2.0/(t-b), 0.0, 0.0, //
        //             0.0, 0.0, 0.5, 0.0, //
        //             (l+r)/(l-r), (t+b)/(b-t), 0.5, 1.0, //
        //         ],
        //     },
        // };
        // #define D3DTS_WORLDMATRIX(index) (D3DTRANSFORMSTATETYPE)(index + 256)
        // #define D3DTS_WORLD  D3DTS_WORLDMATRIX(0)
        // device.SetTransform(D3DTRANSFORMSTATETYPE(256), &MAT_IDENTITY)?;
        // device.SetTransform(D3DTS_VIEW, &MAT_IDENTITY)?;
        // device.SetTransform(D3DTS_PROJECTION, &mat_proj)?;

        Ok(())
    }

    fn upload_geometry(
        &mut self,
        device: &IDirect3DDevice9,
        clipped_meshes: &[ClippedMesh],
    ) -> Result<Vec<CoalescedDraw>, Error> {
        // compute total sizes of geometry so we know whether we have to resize
        let total_vertices = clipped_meshes
            .iter()
            .map(|mesh| mesh.1.vertices.len())
            .sum();
        let total_indices = clipped_meshes.iter().map(|mesh| mesh.1.indices.len()).sum();

        // lock (and recreate for range size if necessary! thanks Resizing<T>)
        let mut vb = self.vertex_buffer.lock(device, 0..total_vertices)?;
        let mut ib = self.index_buffer.lock(device, 0..total_indices)?;

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

            // push draw call metadata to a list we'll output after upload is done
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

            // copy this mesh's geometry to the vb and ib
            for (vert, dest) in shape.vertices[vertex_offset..vertex_offset + vertex_count]
                .iter()
                .zip(vb.iter_mut())
            {
                let c: Rgba = vert.color.into();
                *dest = CustomVertex {
                    pos: vert.pos.into(),
                    uv: vert.uv.into(),
                    col: c.to_array(),
                };
            }
            ib[index_offset..index_offset + index_count].copy_from_slice(&shape.indices);

            // and move on so we don't write over our own data
            vertex_offset += vertex_count;
            index_offset += index_count;
        }

        Ok(draws)
    }

    pub fn paint(
        &mut self,
        device: &IDirect3DDevice9,
        viewport_size: [u32; 2],
    ) -> Result<(), Error> {
        let shapes = mem::take(&mut self.shapes);
        let mut textures_delta = std::mem::take(&mut self.textures_delta);

        for (id, image_delta) in textures_delta.set {
            // apply texture
            // NOTE: D3DPOOL_MANAGED
            // SEE: https://stackoverflow.com/questions/14955954/update-directx-texture
            debug!(id=?id, whole=image_delta.is_whole(), "[texid {:?}]: applying delta (size {:?}, pos {:?})", id, image_delta.image.size(), image_delta.pos);
            debug!(id=?id, "[texid {:?}]: delta is of type {}", id, match image_delta.image {
                ImageData::Color(_) => "color",
                ImageData::Alpha(_) => "alpha",
            });

            if image_delta.is_whole() {
                let texture = unsafe { Texture::create(device, image_delta.image.size()) }?;

                let mut locked_rect = D3DLOCKED_RECT {
                    Pitch: 0,
                    pBits: ptr::null_mut(),
                };
                debug!("locking whole texture");
                unsafe { texture.raw().LockRect(0, &mut locked_rect, ptr::null(), 0) }?;

                // upload here or sth
                unsafe {
                    debug!(
                        "locked_rect={{pitch={:#x}, pBits={:?}}}",
                        locked_rect.Pitch, locked_rect.pBits
                    );
                    let bits = locked_rect.pBits as *mut u8;
                    let pitch = locked_rect.Pitch as usize;
                    let height = image_delta.image.height();
                    let width = image_delta.image.width();
                    for y in 0..height {
                        let gfx_mem_row = slice::from_raw_parts_mut(
                            bits.add(pitch * y) as *mut [u8; 4],
                            pitch / mem::size_of::<[u8; 4]>(),
                        );
                        let pix_iter = match image_delta.image {
                            ImageData::Color(ref i) => Box::new(i.pixels.iter().cloned())
                                as Box<dyn Iterator<Item = Color32>>,
                            ImageData::Alpha(ref i) => {
                                Box::new(i.srgba_pixels(1.0)) as Box<dyn Iterator<Item = Color32>>
                            }
                        }
                        .map(color32_to_argb);

                        for (pix, dst) in pix_iter.skip(width * y).take(width).zip(gfx_mem_row) {
                            *dst = pix;
                        }
                    }
                }

                debug!("unlocking texture");
                // TODO(petra) use a guard abstraction
                unsafe { texture.raw().UnlockRect(0) }?;

                let old = self.textures.insert(id, texture);
                drop(old);
            }
        }

        let clipped_meshes = self.egui_ctx.tessellate(shapes);

        // save old state (will be restored on drop)
        let _state_guard = unsafe { StateGuard::backup(device) }?;

        // set up our pipeline state for egui rendering
        unsafe { self.setup_dx_state(device, viewport_size) }?;

        // scan through meshes and upload merged vert/index lists so we only upload
        // a single vtx buffer and a single idx buffer.
        let draws = self.upload_geometry(device, &clipped_meshes)?;

        let mut last_tex = None;
        for draw in draws {
            if last_tex != Some(draw.texture_id) {
                // need to switch used texture for this draw call!
                unsafe {
                    device.SetTexture(0, self.textures.get(draw.texture_id)?.raw())?;
                }
                last_tex = Some(draw.texture_id);
            }

            unsafe {
                // set up vb and ib for draw
                device.SetStreamSource(
                    0,
                    self.vertex_buffer.raw(),
                    0,
                    mem::size_of::<CustomVertex>() as u32,
                )?;
                device.SetVertexDeclaration(self.vertex_buffer.backing().decl())?;
                device.SetIndices(self.index_buffer.raw())?;

                // do the (clipped) draw
                device.SetScissorRect(&draw.scissors)?;
                device.DrawIndexedPrimitive(
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
