use anyhow::Result;
use rand::seq::SliceRandom;
use zxcvbn::zxcvbn;

const UPPER_CASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER_CASE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const NUMBER: &[u8] = b"123456789";
const SYMBOL: &[u8] = b"!@#$^&*_";

pub fn process_gen_pass(
    length: u8,
    uppercase: bool,
    lowercase: bool,
    number: bool,
    symbol: bool,
) -> Result<()> {
    let mut password = Vec::new();
    let mut chars = Vec::new();

    if uppercase {
        chars.extend_from_slice(UPPER_CASE);
        password.push(*UPPER_CASE.choose(&mut rand::thread_rng()).unwrap());
    }

    if lowercase {
        chars.extend_from_slice(LOWER_CASE);
        password.push(*LOWER_CASE.choose(&mut rand::thread_rng()).unwrap());
    }

    if number {
        chars.extend_from_slice(NUMBER);
        password.push(*NUMBER.choose(&mut rand::thread_rng()).unwrap());
    }

    if symbol {
        chars.extend_from_slice(SYMBOL);
        password.push(*SYMBOL.choose(&mut rand::thread_rng()).unwrap());
    }

    let mut rng = rand::thread_rng();
    for _ in 0..(length - password.len() as u8) {
        let c = chars
            .choose(&mut rng)
            .expect("chars won't be empty in this context");
        password.push(*c);
    }

    password.shuffle(&mut rng);

    let final_password = String::from_utf8(password)?;
    println!("{}", final_password);

    let estimate = zxcvbn(&final_password, &[]).unwrap();
    eprintln!("{}", estimate.score());

    Ok(())
}
