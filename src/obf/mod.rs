use std::fs;

mod ipv4;
mod ipv6;
mod mac;
mod uuid;
mod words;

use ipv4::{obfuscate_ipv4, deobfuscate_ipv4};
use ipv6::{obfuscate_ipv6, deobfuscate_ipv6};
use mac::{obfuscate_mac, deobfuscate_mac};
use uuid::{obfuscate_uuid, deobfuscate_uuid};
use words::{obfuscate_words, deobfuscate_words};

/// 读取二进制文件并进行混淆，返回混淆后的数据
pub fn obfuscate_file(file_path: &str, technique: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // 获取当前可执行文件所在目录
    let current_dir = std::env::current_dir()?;
    let full_path = current_dir.join(file_path);
    println!("Looking for file at: {:?}", full_path);
    
    let buffer = fs::read(&full_path)?;
    println!("Successfully read file, size: {} bytes", buffer.len());
    
    let mut buffer_vec = buffer.to_vec();
    
    match technique {
        "ipv4" => Ok(obfuscate_ipv4(&mut buffer_vec)),
        "ipv6" => Ok(obfuscate_ipv6(&mut buffer_vec)),
        "mac" => Ok(obfuscate_mac(&mut buffer_vec)),
        "uuid" => Ok(obfuscate_uuid(&mut buffer_vec)),
        "words" => Ok(obfuscate_words(&mut buffer_vec)),
        _ => Err("Unsupported technique".into()),
    }
}

/// 解混淆数据，返回字节数组
pub fn deobfuscate_data(data: &[String], technique: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let str_data: Vec<&str> = data.iter().map(|s| s.as_str()).collect();
    
    match technique {
        "ipv4" => deobfuscate_ipv4(str_data),
        "ipv6" => deobfuscate_ipv6(str_data),
        "mac" => deobfuscate_mac(str_data),
        "uuid" => deobfuscate_uuid(str_data),
        "words" => deobfuscate_words(str_data),
        _ => Err("Unsupported technique".into()),
    }
}