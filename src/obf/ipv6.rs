use std::net::Ipv6Addr;

/// 混淆函数：返回IPv6字符串数组
pub(crate) fn obfuscate_ipv6(shellcode: &mut Vec<u8>) -> Vec<String> {
    if shellcode.len() % 16 != 0 {
        shellcode.resize((shellcode.len() + 15) / 16 * 16, 0);
    }

    let mut result = Vec::new();
    for chunk in shellcode.chunks(16) {
        let ip = format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
             {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            chunk[0], chunk[1], chunk[2], chunk[3],
            chunk[4], chunk[5], chunk[6], chunk[7],
            chunk[8], chunk[9], chunk[10], chunk[11],
            chunk[12], chunk[13], chunk[14], chunk[15]
        );
        result.push(ip);
    }
    result
}

/// 解混淆函数：返回字节数组
pub(crate) fn deobfuscate_ipv6(list_ips: Vec<&str>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut deobfuscated_ips: Vec<u8> = Vec::with_capacity(list_ips.len() * 16);

    for ip in list_ips {
        let ip_addr = ip
            .parse::<Ipv6Addr>()
            .map_err(|e| format!("Failed to parse IPv6 '{}': {}", ip, e))?;

        for segment in ip_addr.segments() {
            deobfuscated_ips.extend_from_slice(&segment.to_be_bytes());
        }
    }

    Ok(deobfuscated_ips)
}