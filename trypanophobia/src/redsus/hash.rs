use crate::win32::c_char;

const fn fx_hash_step(state: u32, x: u32) -> u32 {
    const K: u32 = 0x517cc1b7;
    (state.rotate_left(5) ^ x).wrapping_mul(K)
}

pub unsafe fn fx_hash_buf(mut input: *const c_char) -> u32 {
    let mut state = 0;
    while *input != 0 {
        state = fx_hash_step(state, *input as u32);
        input = input.add(1);
    }
    state
}

pub const fn fx_hash(input: &[u8]) -> u32 {
    let mut state = 0;
    let mut i = 0;
    while i < input.len() {
        state = fx_hash_step(state, input[i] as u32);
        i += 1;
    }
    state
}
