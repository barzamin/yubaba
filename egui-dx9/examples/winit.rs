use std::{ptr, rc::Rc};

use egui_dx9::EguiDx9;
use raw_window_handle::{HasRawWindowHandle, RawWindowHandle};
use windows::Win32::{
    Foundation::HWND,
    Graphics::Direct3D9::{
        Direct3DCreate9, IDirect3DDevice9, D3DADAPTER_DEFAULT, D3DCREATE_SOFTWARE_VERTEXPROCESSING,
        D3DDEVTYPE_HAL, D3DFMT_R5G6B5, D3DMULTISAMPLE_NONE, D3DPRESENT_INTERVAL_DEFAULT,
        D3DPRESENT_PARAMETERS, D3DPRESENT_RATE_DEFAULT, D3DSWAPEFFECT_DISCARD, D3D_SDK_VERSION,
    },
    System::SystemServices::D3DCLEAR_TARGET,
};
use winit::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};

const WIN_WIDTH: u32 = 800;
const WIN_HEIGHT: u32 = 800;

fn main() {
    tracing_subscriber::fmt::init();

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("dx9 egui")
        .with_resizable(false)
        .with_inner_size(LogicalSize {
            width: WIN_WIDTH,
            height: WIN_HEIGHT,
        })
        .build(&event_loop)
        .unwrap();

    let hwnd = HWND(match window.raw_window_handle() {
        RawWindowHandle::Win32(handle) => handle.hwnd,
        _ => panic!("how"),
    } as isize);

    let dx9 = unsafe { Direct3DCreate9(D3D_SDK_VERSION) }.expect("couldn't create d3d9 context");
    // TODO(petra): review to make sure this works for egui
    let mut present_params = unsafe {
        D3DPRESENT_PARAMETERS {
            hDeviceWindow: hwnd,
            BackBufferCount: 1,
            MultiSampleType: D3DMULTISAMPLE_NONE,
            MultiSampleQuality: 0,
            SwapEffect: D3DSWAPEFFECT_DISCARD,
            Flags: 0,
            FullScreen_RefreshRateInHz: D3DPRESENT_RATE_DEFAULT,
            PresentationInterval: D3DPRESENT_INTERVAL_DEFAULT as u32,
            BackBufferFormat: D3DFMT_R5G6B5,
            EnableAutoDepthStencil: false.into(),
            Windowed: true.into(),
            BackBufferWidth: WIN_WIDTH as u32,
            BackBufferHeight: WIN_HEIGHT as u32,
            ..core::mem::zeroed()
        }
    };

    let mut device: Option<IDirect3DDevice9> = None;
    // let r =
    unsafe {
        dx9.CreateDevice(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            hwnd,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING as _,
            &mut present_params,
            &mut device,
        )
    }
    .expect("couldn't create d3d9 device");

    let device = device.expect("d3d9 device was null");
    let mut egui_backend =
        egui_dx9::EguiDx9::new(&device).expect("couldnt initialize the egui dx9 backend");

    let mut clear_color = [0.1, 0.1, 0.1];

    event_loop.run(move |event, _, ctlflow| match event {
        Event::MainEventsCleared => {
            window.request_redraw();
        }
        Event::RedrawRequested(_) => unsafe {
            let needs_repaint = egui_backend.run(|egui_ctx| {
                egui::SidePanel::left("my_side_panel").show(egui_ctx, |ui| {
                    ui.heading("Hello World!");
                    if ui.button("Quit").clicked() {
                        // quit = true;
                    }
                    ui.color_edit_button_rgb(&mut clear_color);
                });
            });

            device
                .Clear(0, ptr::null(), D3DCLEAR_TARGET as _, 0xffa0_0aaa, 1.0, 0)
                .unwrap();

            device.BeginScene().unwrap();

            egui_backend
                .paint(&device, window.inner_size().into())
                .unwrap();

            device.EndScene().unwrap();
            device
                .Present(ptr::null(), ptr::null(), None, ptr::null())
                .unwrap();
        },
        Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } => {
            *ctlflow = ControlFlow::Exit;
        }
        // Event::LoopDestroyed => unsafe {
        // }
        _ => (),
    });
}
