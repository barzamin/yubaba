//
// Generated by Microsoft (R) HLSL Shader Compiler 9.29.952.3111
//
//   fxc C:\Users\erin\Documents\yubaba\egui-dx9\src\shader\shader.hlsl
//    /Evs_main /Tvs_3_0
//    /FoC:\Users\erin\Documents\yubaba\egui-dx9\src\shader/vert.bin
//    /FcC:\Users\erin\Documents\yubaba\egui-dx9\src\shader/vert.asm
//
    vs_3_0
    def c0, 1, 0, 0, 0
    dcl_position v0
    dcl_texcoord v1
    dcl_color v2
    dcl_position o0
    dcl_color o1
    dcl_texcoord o2.xy
    mad o0, v0.xyxx, c0.xxyy, c0.yyyx
    mov o1, v2
    mov o2.xy, v1

// approximately 3 instruction slots used
