use std::{
    ffi::{c_void},
    slice::{from_raw_parts, from_raw_parts_mut},
};
use windows::{
    core::{s},
    Win32::{
        Foundation::HWND,
        System::LibraryLoader::{GetProcAddress, LoadLibraryA},
        System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
        UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE},
        UI::WindowsAndMessaging::{MB_OK, MESSAGEBOX_RESULT},
    },
};

// 定义回调函数类型
pub type HookCallback = fn();

// 用于保存外部传入的回调函数
static mut USER_CALLBACK: Option<HookCallback> = None;

extern "system" fn my_message_box_a(
    _: HWND,
    _: *const i8,
    _: *const i8,
    _: MESSAGEBOX_STYLE,
) -> MESSAGEBOX_RESULT {
    unsafe {
        // 调用用户传入的自定义函数
        if let Some(callback) = USER_CALLBACK {
            callback();
        }

        // 可选：你也可以把原始参数传给回调（见扩展部分）
        // 例如：callback(text, caption);

        // 显示 Hooked 的弹窗
        // MessageBoxW(hwnd, w!("HOOK"), w!("ENABLED!"), u_type)

        MESSAGEBOX_RESULT(0)
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

    fn initialize(&mut self, trampoline: &[u8], old_protect: &mut PAGE_PROTECTION_FLAGS) -> bool {
        unsafe {
            let result = VirtualProtect(
                self.function_hook,
                trampoline.len(),
                PAGE_EXECUTE_READWRITE,
                old_protect,
            );
            if result.is_err() {
                // eprintln!("[!] VirtualProtect Failed With Error {:?}", result.err());
                return false;
            }

            let bytes = from_raw_parts(self.function_hook.cast::<u8>(), trampoline.len());
            self.bytes_original.copy_from_slice(bytes);
        }
        true
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

    let hmodule = unsafe { LoadLibraryA(s!("user32.dll")).unwrap() };
    let func = unsafe { GetProcAddress(hmodule, s!("MessageBoxA")).unwrap() };

    let mut oldprotect = PAGE_PROTECTION_FLAGS(0);
    let mut hook = Hook::new(my_message_box_a as *mut c_void, func as *mut c_void);

    if hook.initialize(&trampoline, &mut oldprotect) {
        hook.install_hook(&mut trampoline);
    } else {
        // eprintln!("[!] Failed to Apply Hook!");
        return;
    }

    unsafe {
        // 触发钩子
        MessageBoxA(HWND(0), s!("Test Message"), s!("Test"), MB_OK);
        // println!("[+] Hook disabled");

        // 恢复原始字节
        let restore_target = from_raw_parts_mut(hook.function_hook.cast::<u8>(), trampoline.len());
        restore_target.copy_from_slice(&hook.bytes_original);

        // 恢复内存保护
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        let addr = VirtualProtect(hook.function_hook, trampoline.len(), oldprotect, &mut old_protect);
        if addr.is_err() {
            // eprintln!("[!] VirtualProtect Failed With Error {:?}", addr.err());
            return;
        }

        // 再次调用，应显示原始 MessageBoxA
        // MessageBoxA(HWND(0), s!("Test Message"), s!("Test"), MB_OK);
    }

    // println!("[+] Finish");
}