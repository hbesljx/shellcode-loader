use stegano_util::luma_lsb_hide;
use stegano_util::luma_lsb_read;

pub fn hide_lsb(img_path:&str,bin_path:&str){
    let _=luma_lsb_hide(img_path, bin_path);
}

pub fn read_lsb(img_path:&str)->Result<Vec<u8>,String>{
    let res=luma_lsb_read(img_path);
    res
}