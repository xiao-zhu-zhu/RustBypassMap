use base64::{alphabet, engine, Engine as _};
use rand::{Rng, SeedableRng};
use rand::prelude::StdRng;

// 混淆base64 顺序，必须64个不同的字符串
const ALPHABET: &str = "/wVO(Mb&%x,UC<#:Zj}zliyK-!_$vH*DFIe{dm^AXng>?.N;SB~|TEaQ+c)r@520";

pub fn base64_encode_with_random(input: &[u8], key: u64) -> String {
    let alphabet =
        alphabet::Alphabet::new(ALPHABET).unwrap();
    let crazy_config = engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_encode_padding(true)
        .with_decode_padding_mode(engine::DecodePaddingMode::RequireNone);

    let crazy_engine = engine::GeneralPurpose::new(&alphabet, crazy_config);


    let mut rng = StdRng::seed_from_u64(key);
    let random_value: u8 = rng.gen();

    let mut data = input.to_vec();
    for byte in &mut data {
        *byte ^= random_value;
    }

    crazy_engine.encode(&data)
}

pub fn base64_decode_with_random(input: &str, key: u64) -> Result<Vec<u8>, base64::DecodeError> {
    let mut rng = StdRng::seed_from_u64(key);
    let random_value: u8 = rng.gen();
    let alphabet =
        alphabet::Alphabet::new(ALPHABET).unwrap();
    let crazy_config = engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_encode_padding(true)
        .with_decode_padding_mode(engine::DecodePaddingMode::RequireNone);

    let crazy_engine = engine::GeneralPurpose::new(&alphabet, crazy_config);
    let mut data =     crazy_engine.decode(input)?;

    for byte in &mut data {
        *byte ^= random_value;
    }

    Ok(data)
}


