//
// Generated by Microsoft (R) HLSL Shader Compiler 9.29.952.3111
//
//   fxc C:\Users\erin\Documents\yubaba\egui-dx9\src\shader\shader.hlsl
//    /Eps_main /Tps_3_0
//    /FoC:\Users\erin\Documents\yubaba\egui-dx9\src\shader/pix.bin
//    /FcC:\Users\erin\Documents\yubaba\egui-dx9\src\shader/pix.asm
//
//
// Parameters:
//
//   Texture2D sampler0+texture0;
//
//
// Registers:
//
//   Name              Reg   Size
//   ----------------- ----- ----
//   sampler0+texture0 s0       1
//

    ps_3_0
    dcl_color v0
    dcl_texcoord v1.xy
    dcl_2d s0
    texld r0, v1, s0
    mul oC0, r0, v0

// approximately 2 instruction slots used (1 texture, 1 arithmetic)