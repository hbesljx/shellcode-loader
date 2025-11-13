use std::{
    ffi::{CStr, c_void}, 
    slice::from_raw_parts
};
use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
};
use windows::{
    core::{Error, Result, HSTRING}, 
    Win32::{
        Foundation::E_FAIL,
    }};
use windows::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64,
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, 
        IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
};

pub(crate) fn get_function_address(dll_name: &str, function_name: &str) -> Result<*mut c_void> {
    unsafe {
        let dll_base = get_module_address(dll_name)?;

        find_exported_function(dll_base, function_name, dll_name)
    }
}

unsafe fn find_exported_function(
    dll_base: *mut c_void,
    function_name: &str,
    dll_name: &str,  // 接收 dll_name 用于错误消息
) -> Result<*mut c_void> {
    let module = dll_base as usize;
    let dos_header = module as *mut IMAGE_DOS_HEADER;
    if (unsafe { *dos_header }).e_magic != IMAGE_DOS_SIGNATURE {
        return Err(Error::new(E_FAIL, HSTRING::from("INVALID DOS SIGNATURE")));
    }

    let nt_header = (module + (unsafe { *dos_header }).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (unsafe { *nt_header }).Signature != IMAGE_NT_SIGNATURE {
        return Err(Error::new(E_FAIL, HSTRING::from("INVALID NT SIGNATURE")));
    }

    // Locate export directory from DataDirectory[0]
    let export_dir = (module + (unsafe { *nt_header }).OptionalHeader.DataDirectory[0].VirtualAddress as usize) 
        as *const IMAGE_EXPORT_DIRECTORY;

    // 获取导出名称数组
    let names = unsafe { from_raw_parts(
        (module + (*export_dir).AddressOfNames as usize) as *const u32, 
        (*export_dir).NumberOfNames as usize
    ) };

    // 获取序数数组
    let ordinals = unsafe { from_raw_parts(
        (module + (*export_dir).AddressOfNameOrdinals as usize) as *const u16, 
        (*export_dir).NumberOfNames as usize
    ) };

    // 获取函数地址数组
    let functions = unsafe { from_raw_parts(
        (module + (*export_dir).AddressOfFunctions as usize) as *const u32, 
        (*export_dir).NumberOfFunctions as usize
    ) };

    // 遍历所有导出名称
    for i in 0..(unsafe { *export_dir }).NumberOfNames as usize {
        let name_ptr = (module + names[i] as usize) as *const i8;
        let name = unsafe { CStr::from_ptr(name_ptr)
            .to_str()
            .unwrap_or("") };

        if name == function_name {
            let ordinal = ordinals[i] as usize;
            let address = (dll_base as usize + functions[ordinal] as usize) as *mut c_void;
            return Ok(address);
        }
    }

    let error_message = format!("Function '{}' not found in {}", function_name, dll_name);
    Err(Error::new(E_FAIL, HSTRING::from(error_message)))
}

pub(crate) fn get_module_address(dll: &str) -> Result<*mut c_void> {
    unsafe {
        let peb = NtCurrentPeb();
        let ldr = (*peb).Ldr;
        let mut list_entry = (*ldr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
    
        while !(*list_entry).DllBase.is_null() {
            let buffer = from_raw_parts(
                (*list_entry).BaseDllName.Buffer,
                ((*list_entry).BaseDllName.Length / 2) as usize,
            );
    
            let dll_name = String::from_utf16_lossy(&buffer).to_lowercase();
            if dll == dll_name {
                return Ok((*list_entry).DllBase.cast());
            }
    
            list_entry = (*list_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        }
    }
        
    Err(Error::new(E_FAIL, HSTRING::from("Module Not found")))
}

#[inline(always)]
#[allow(non_snake_case)]
fn NtCurrentPeb() -> *const PEB {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        return __readgsqword(0x60) as *const PEB;

        #[cfg(target_arch = "x86")]
        return __readfsdword(0x30) as *const PEB;
    }
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
        );
    }
    out
}

#[inline(always)]
#[cfg(target_arch = "x86")]
unsafe fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    core::arch::asm!(
        "mov {:e}, fs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}