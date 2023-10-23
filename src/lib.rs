extern "C" {
    fn boost_get_last_bootup_time(buffer: *mut u8, max_length: u32, real_length: *mut u32) -> i32;
}

pub fn get() -> Result<String, String> {
    const MAX_LENGTH: usize = 512;
    let mut buffer: [u8; MAX_LENGTH] = [0; MAX_LENGTH];
    let mut real_length: u32 = 0;

    let result = unsafe {
        boost_get_last_bootup_time(buffer.as_mut_ptr(), MAX_LENGTH as u32, &mut real_length)
    };

    if result == 0 && real_length < MAX_LENGTH as u32 && real_length > 0 {
        return String::from_utf8(buffer[..((real_length - 1) as usize)].to_vec())
            .map_err(|_| "Invalid UTF-8 sequence".to_string());
    }
    Err("Failed to get last bootup time".to_string())
}

#[test]
fn test() {
    println!("{:?}", get());
}
