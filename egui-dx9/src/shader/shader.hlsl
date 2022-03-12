// --- vertex shader ---
struct vs_in {
    float2 pos : POSITION;
    float2 uv : TEXCOORD;
    float4 color : COLOR0;
};

struct vs_out {
    float4 clip : SV_POSITION;
    float4 color : COLOR0;
    float2 uv : TEXCOORD;
};

vs_out vs_main(vs_in input) {
    vs_out output;

    output.clip = float4(input.pos, 0.0, 1.0);
    output.color = input.color;
    output.uv = input.uv;

    return output;
}

// --- pixel shader ---
sampler sampler0;
Texture2D texture0;

float4 ps_main(vs_out input) : COLOR {
    // // *nota bene*: rgba
    // float3 albedo = pow(
    //     input.color.xyz,
    //     (1.0/2.2).xxx, // gamma
    // );
    // float alpha = input.color.w * texture0.Sample(sampler0, input.uv).x;
    return input.color * texture0.Sample(sampler0, input.uv);   
}
