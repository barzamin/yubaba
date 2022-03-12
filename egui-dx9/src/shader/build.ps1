$sdk_base = "C:\Program Files (x86)\Microsoft DirectX SDK (June 2010)\"

&"$sdk_base\Utilities\bin\x86\fxc.exe" "$PSScriptRoot\shader.hlsl" /Evs_main /Tvs_3_0 /Fo"$PSScriptRoot/vert.bin" /Fc"$PSScriptRoot/vert.asm"
&"$sdk_base\Utilities\bin\x86\fxc.exe" "$PSScriptRoot\shader.hlsl" /Eps_main /Tps_3_0 /Fo"$PSScriptRoot/pix.bin" /Fc"$PSScriptRoot/pix.asm"