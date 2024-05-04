use std::io::Read;

use anyhow::Result;
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Claims {
    exp: usize,
    aud: Option<String>,
    iat: Option<usize>,
    iss: Option<String>,
    nbf: Option<usize>,
    sub: Option<String>,
}

pub fn process_jwt_sign(
    algorithm: Algorithm,
    key: &mut dyn Read,
    exp: usize,
    aud: Option<String>,
    sub: Option<String>,
) -> Result<String> {
    let my_claims = Claims {
        exp,
        aud,
        sub,
        ..Default::default()
    };
    let header = Header {
        alg: algorithm,
        ..Default::default()
    };
    let mut buf = String::new();
    key.read_to_string(&mut buf)?;
    // avoid accidental newlines
    let buf = buf.trim();

    let token = match encode(
        &header,
        &my_claims,
        &EncodingKey::from_secret(buf.as_bytes()),
    ) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    Ok(token)
}

pub fn process_jwt_verify(
    algorithm: Algorithm,
    key: &mut dyn Read,
    token: String,
    aud: Option<String>,
    sub: Option<String>,
) -> Result<TokenData<Claims>> {
    let mut buf = String::new();
    key.read_to_string(&mut buf)?;
    // avoid accidental newlines
    let buf = buf.trim();
    let mut validation = Validation::new(algorithm);
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    validation.sub = sub;
    if let Some(s) = aud {
        validation.set_audience(&[s]);
    }
    let token_data: jsonwebtoken::TokenData<Claims> = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(buf.as_bytes()),
        &validation,
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => {
                println!("Token is invalid");
                return Err(err.into());
            }
            ErrorKind::ExpiredSignature => {
                println!("Token is expired");
                return Err(err.into());
            }
            _ => {
                println!("Error");
                return Err(err.into());
            }
        },
    };
    Ok(token_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_reader;

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let algorithm = Algorithm::HS512;
        let aud = Some("device1".to_string());
        let sub = Some("acme".to_string());
        let mut key = KEY;
        process_jwt_sign(algorithm, &mut key, 10000000000, aud.clone(), sub.clone())?;
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader: Box<dyn Read> = get_reader("fixtures/blake3.txt")?;
        let algorithm = Algorithm::HS256;
        let aud = Some("device1".to_string());
        let sub = Some("acme".to_string());
        let mut key = KEY;
        let token = process_jwt_sign(algorithm, &mut key, 10000000000, aud.clone(), sub.clone())?;
        println!("Token: {}", token);
        let token_data =
            process_jwt_verify(algorithm, &mut reader, token, aud.clone(), sub.clone())?;
        assert_eq!(token_data.claims.aud, aud);
        assert_eq!(token_data.claims.sub, sub);
        Ok(())
    }
}
