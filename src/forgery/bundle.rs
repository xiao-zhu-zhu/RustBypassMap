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