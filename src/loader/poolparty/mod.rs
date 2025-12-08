use crate::loader::poolparty::party_time_1::InjectionError;

pub(crate) mod party_time_1;
pub(crate) mod common;

pub fn party_time_1(shellcode: &[u8], pid: u32) -> Result<(), InjectionError> {
    party_time_1::party_time_1(shellcode, pid)
}