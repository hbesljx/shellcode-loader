use std::ffi::OsStr;

use sysinfo::{System,Disks};

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

pub fn is_sandbox(cpus_count:u32,rams_size:u32,proc_count:u32,disk_size:u32)->bool{
    let mut sys=System::new();
    sys.refresh_all();
    let cpus=count_cpus();
    let rams=count_rams(&sys);
    let proc=count_proc(&sys);
    let disk=count_disk();

    return cpus<cpus_count || rams<rams_size || proc<proc_count || disk<disk_size
}