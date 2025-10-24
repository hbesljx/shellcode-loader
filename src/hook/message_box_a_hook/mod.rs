use std::{
    ffi::{c_void},
    slice::{from_raw_parts, from_raw_parts_mut},
};
use crate::iat::get_function_address;

// 定义回调函数类型
pub type HookCallback = fn();

// 用于保存外部传入的回调函数
static mut USER_CALLBACK: Option<HookCallback> = None;

extern "system" fn my_message_box_a(
    _: isize,           // hWnd
    _: *const u8,       // lpText
    _: *const u8,       // lpCaption
    _: u32,             // uType
) -> i32 {
    unsafe {
        // 调用用户传入的自定义函数
        if let Some(callback) = USER_CALLBACK {
            callback();
        }

        // 返回 0 表示不显示原始消息框，或者你可以返回其他值
        0
    }
}

struct Hook {
    #[cfg(target_arch = "x86_64")]
    bytes_original: [u8; 13],

    #[cfg(target_arch = "x86")]
    bytes_original: [u8; 7],

    function_run: *mut c_void,
    function_hook: *mut c_void,
}

impl Hook {
    fn new(function_run: *mut c_void, function_hook: *mut c_void) -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            bytes_original: [0; 13],
            #[cfg(target_arch = "x86")]
            bytes_original: [0; 7],
            function_run,
            function_hook,
        }
    }

    fn initialize(&mut self, trampoline: &[u8], old_protect: &mut u32) -> bool {
        unsafe {
            // 使用自定义方法获取 VirtualProtect 地址
            if let Ok(virtual_protect_addr) = get_function_address("kernel32.dll", "VirtualProtect") {
                let virtual_protect_fn: unsafe extern "system" fn(
                    *mut c_void, // lpAddress
                    usize,       // dwSize
                    u32,         // flNewProtect
                    *mut u32,    // lpflOldProtect
                ) -> i32 = std::mem::transmute(virtual_protect_addr);

                let result = virtual_protect_fn(
                    self.function_hook,
                    trampoline.len(),
                    PAGE_EXECUTE_READWRITE,
                    old_protect,
                );

                if result == 0 {
                    return false;
                }

                let bytes = from_raw_parts(self.function_hook.cast::<u8>(), trampoline.len());
                self.bytes_original.copy_from_slice(bytes);
                true
            } else {
                false
            }
        }
    }

    fn install_hook(&self, trampoline: &mut [u8]) {
        unsafe {
            #[cfg(target_arch = "x86_64")]
            {
                let func_addr = self.function_run as u64;
                trampoline[2..10].copy_from_slice(&func_addr.to_ne_bytes());
            }

            #[cfg(target_arch = "x86")]
            {
                let func_addr = self.function_run as u32;
                trampoline[1..5].copy_from_slice(&func_addr.to_ne_bytes());
            }

            let dst_code = from_raw_parts_mut(self.function_hook.cast::<u8>(), trampoline.len());
            dst_code.copy_from_slice(trampoline);
        }
    }

    fn restore(&self) {
        unsafe {
            // 恢复原始字节
            let restore_target = from_raw_parts_mut(self.function_hook.cast::<u8>(), self.bytes_original.len());
            restore_target.copy_from_slice(&self.bytes_original);

            // 恢复内存保护
            let mut old_protect = 0u32;
            if let Ok(virtual_protect_addr) = get_function_address("kernel32.dll", "VirtualProtect") {
                let virtual_protect_fn: unsafe extern "system" fn(
                    *mut c_void,
                    usize,
                    u32,
                    *mut u32,
                ) -> i32 = std::mem::transmute(virtual_protect_addr);

                let _ = virtual_protect_fn(
                    self.function_hook,
                    self.bytes_original.len(),
                    self.get_original_protection(),
                    &mut old_protect,
                );
            }
        }
    }

    fn get_original_protection(&self) -> u32 {
        // 这里应该返回原始的内存保护标志，简化处理返回可读可写可执行
        PAGE_EXECUTE_READWRITE
    }
}

/// 修改后的：接受一个自定义函数作为回调
pub fn message_box_hook(callback: HookCallback) {
    // 保存用户传入的回调函数
    unsafe {
        USER_CALLBACK = Some(callback);
    }

    #[cfg(target_arch = "x86_64")]
    let mut trampoline: [u8; 13] = [
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, function
        0x41, 0xFF, 0xE2, // jmp r10
    ];

    #[cfg(target_arch = "x86")]
    let mut trampoline: [u8; 7] = [
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, function
        0xFF, 0xE0, // jmp eax
    ];

    // 使用自定义方法获取 MessageBoxA 地址
    let func = match get_function_address("user32.dll", "MessageBoxA") {
        Ok(addr) => addr,
        Err(_) => return,
    };

    let mut oldprotect = 0u32;
    let mut hook = Hook::new(my_message_box_a as *mut c_void, func);

    if !hook.initialize(&trampoline, &mut oldprotect) {
        return;
    }

    hook.install_hook(&mut trampoline);

    unsafe {
        // 触发钩子 - 使用自定义方法调用 MessageBoxA
        if let Ok(message_box_a_addr) = get_function_address("user32.dll", "MessageBoxA") {
            let message_box_a_fn: unsafe extern "system" fn(isize, *const u8, *const u8, u32) -> i32 = 
                std::mem::transmute(message_box_a_addr);
            
            let text = b"Test Message\0";
            let caption = b"Test\0";
            message_box_a_fn(0, text.as_ptr(), caption.as_ptr(), 0);
        }

        // 恢复钩子
        hook.restore();

        // 再次调用，应显示原始 MessageBoxA
        if let Ok(message_box_a_addr) = get_function_address("user32.dll", "MessageBoxA") {
            let message_box_a_fn: unsafe extern "system" fn(isize, *const u8, *const u8, u32) -> i32 = 
                std::mem::transmute(message_box_a_addr);
            
            let text = b"Test Message\0";
            let caption = b"Test\0";
            message_box_a_fn(0, text.as_ptr(), caption.as_ptr(), 0);
        }
    }
}

// 常量定义
const PAGE_EXECUTE_READWRITE: u32 = 0x40;