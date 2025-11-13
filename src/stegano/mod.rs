use image::{GenericImageView, ImageBuffer, Luma, Rgb, RgbImage};
use std::path::Path;

pub fn hide_lsb(img_path:&str,bin_path:&str){
    let _=luma_lsb_hide(img_path, bin_path);
}

pub fn read_lsb(img_path:&str)->Result<Vec<u8>,String>{
    let res=luma_lsb_read(img_path);
    res
}

pub fn luma_lsb_hide(img_path:&str,bin_path:&str)->Result<(), &'static str>{
    hide(img_path, bin_path)
}

pub fn luma_lsb_read(output_path:&str)->Result<Vec<u8>,String>{
    read(output_path)
}

pub fn rgb_to_ycbcr(r: u8, g: u8, b: u8) -> (u8, u8, u8) {
    let y = ((66 * r as i32 + 129 * g as i32 + 25 * b as i32 + 128) >> 8) + 16;
    let cb = ((-38 * r as i32 - 74 * g as i32 + 112 * b as i32 + 128) >> 8) + 128;
    let cr = ((112 * r as i32 - 94 * g as i32 - 18 * b as i32 + 128) >> 8) + 128;
    (
        y.clamp(0, 255) as u8,
        cb.clamp(0, 255) as u8,
        cr.clamp(0, 255) as u8,
    )
}

pub fn ycbcr_to_rgb(y: u8, cb: u8, cr: u8) -> (u8, u8, u8) {
    let y = y as i32 - 16;
    let cb = cb as i32 - 128;
    let cr = cr as i32 - 128;
    let r = (298 * y + 409 * cr + 128) >> 8;
    let g = (298 * y - 100 * cb - 208 * cr + 128) >> 8;
    let b = (298 * y + 516 * cb + 128) >> 8;
    (
        r.clamp(0, 255) as u8,
        g.clamp(0, 255) as u8,
        b.clamp(0, 255) as u8,
    )
}


fn lsb_one_bit(buff:u8,msg:u8)->u8{ //先隐写1bit到1byte中
    let bit = msg & 1;  //保证是0或1
    (buff & !1) | bit   //嵌入最低位
}
fn lsb(y_buff: &mut ImageBuffer<Luma<u8>, Vec<u8>>, msg: &[u8]) {
    let mut bits = Vec::new();
    for byte in msg.iter() {
        for i in 0..8 {
            bits.push((byte >> i) & 1);
        }
    }

    let mut i = 0;
    for y in 0..y_buff.height() {
        for x in 0..y_buff.width() {
            if i < bits.len() {
                let old = y_buff.get_pixel_mut(x, y);
                old[0] = lsb_one_bit(old[0], bits[i]);
                i += 1;
            } else {
                break;
            }
        }
        if i >= bits.len() {
            break;
        }
    }
}
pub(crate) fn hide(img_path: &str, bin_path: &str) -> Result<(), &'static str> {
    let img = image::open(img_path).unwrap();
    let (width, height) = img.dimensions();

    let msg = std::fs::read(bin_path).expect("读取bin文件失败!");

    let total_bits_needed = (msg.len() + 4) * 8;

    let max_bits_available = (width * height) as usize;

    if total_bits_needed > max_bits_available {
        return Err("图像空间不足");
    }

    let mut y_buff: ImageBuffer<Luma<u8>, Vec<_>> = ImageBuffer::new(width, height);
    let mut cb_buff: ImageBuffer<Luma<u8>, Vec<_>> = ImageBuffer::new(width, height);
    let mut cr_buff: ImageBuffer<Luma<u8>, Vec<_>> = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let [r, g, b, _a] = img.get_pixel(x, y).0;
            let ycbcr = rgb_to_ycbcr(r, g, b);

            y_buff.put_pixel(x, y, Luma([ycbcr.0]));
            cb_buff.put_pixel(x, y, Luma([ycbcr.1]));
            cr_buff.put_pixel(x, y, Luma([ycbcr.2]));
        }
    }

    let mut data_with_len = (msg.len() as u32).to_le_bytes().to_vec();
    data_with_len.extend_from_slice(&msg);  // 在前面加4字节固定头部，记录数据长度

    lsb(&mut y_buff, &data_with_len);

    let mut output_img = RgbImage::new(width, height);
    for y in 0..height {
        for x in 0..width {
            let yval = y_buff.get_pixel(x, y)[0];
            let cbval = cb_buff.get_pixel(x, y)[0];
            let crval = cr_buff.get_pixel(x, y)[0];
            let (r, g, b) = ycbcr_to_rgb(yval, cbval, crval);
            output_img.put_pixel(x, y, Rgb([r, g, b]));
        }
    }
    output_img.save("output.png").expect("保存图片失败");

    Ok(())
}

pub(crate) fn read(output_path: &str) -> Result<Vec<u8>, String> {
    if !Path::new(output_path).exists() {
        return Err(format!("文件不存在: {}", output_path));
    }

    let img = image::open(output_path).map_err(|e| format!("无法打开或解码图片: {}", e))?;
    let (width, height) = img.dimensions();

    let mut y_buff: ImageBuffer<Luma<u8>, Vec<_>> = ImageBuffer::new(width, height);
    let mut cb_buff: ImageBuffer<Luma<u8>, Vec<_>> = ImageBuffer::new(width, height);
    let mut cr_buff: ImageBuffer<Luma<u8>, Vec<_>> = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let [r, g, b, _a] = img.get_pixel(x, y).0;
            let ycbcr = rgb_to_ycbcr(r, g, b);
            y_buff.put_pixel(x, y, Luma([ycbcr.0]));
            cb_buff.put_pixel(x, y, Luma([ycbcr.1]));
            cr_buff.put_pixel(x, y, Luma([ycbcr.2]));
        }
    }

    let mut msg_len_bits = Vec::with_capacity(32);
    let mut flag = 0;
    for y in 0..height {
        for x in 0..width {
            if flag >= 32 {
                break;
            }
            let bit = y_buff.get_pixel(x, y)[0] & 1;
            msg_len_bits.push(bit);
            flag += 1;
        }
        if flag >= 32 {
            break;
        }
    }
    let mut msg_len_bytes = [0u8; 4];
    for i in 0..4 {
        let mut byte = 0u8;
        for j in 0..8 {
            let bit = msg_len_bits[j + i * 8];
            byte |= bit << j;
        }
        msg_len_bytes[i] = byte;
    }
    let data_len = u32::from_le_bytes(msg_len_bytes) as usize;

    let total_bits = (data_len + 4) * 8;
    let mut all_bits = Vec::with_capacity(total_bits);
    let mut count = 0;
    for y in 0..height {
        for x in 0..width {
            if count >= total_bits {
                break;
            }
            let bit = y_buff.get_pixel(x, y)[0] & 1;
            all_bits.push(bit);
            count += 1;
        }
        if count >= total_bits {
            break;
        }
    }

    if all_bits.len() < total_bits {
        return Err("图片中数据不完整，可能未隐藏信息或损坏".to_string());
    }

    let data_bits = &all_bits[32..];
    let mut data_bytes = Vec::with_capacity(data_len);
    for i in 0..data_len {
        let mut byte = 0u8;
        for j in 0..8 {
            let bit = data_bits[j + i * 8];
            byte |= bit << j;
        }
        data_bytes.push(byte);
    }

    Ok(data_bytes)
}