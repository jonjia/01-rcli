use std::io::Read;

use clap::Parser;
use enum_dispatch::enum_dispatch;
use jsonwebtoken::Algorithm;

use crate::{get_reader, process_jwt_sign, process_jwt_verify, CmdExecutor};

use super::parse_input_file;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum JwtSubCommand {
    #[command(about = "Sign a json web token")]
    Sign(JwtSignOpts),

    #[command(about = "Verify a json web token")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(long, default_value = "HS256")]
    pub algorithm: Algorithm,

    #[arg(long, value_parser = parse_input_file)]
    pub key: String,

    #[arg(long)]
    pub exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)

    #[arg(long, default_value = None)]
    pub aud: Option<String>, // Optional. Audience

    #[arg(long, default_value = None)]
    pub sub: Option<String>, // Optional. Subject (whom token refers to)
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(long, default_value = "HS256")]
    pub algorithm: Algorithm,

    #[arg(long, value_parser = parse_input_file)]
    pub key: String,

    #[arg(long)]
    pub token: String,

    #[arg(long)]
    pub aud: Option<String>, // Optional. Audience

    #[arg(long)]
    pub sub: Option<String>, // Optional. Subject (whom token refers to)
}

impl CmdExecutor for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader: Box<dyn Read> = get_reader(&self.key)?;
        let token = process_jwt_sign(self.algorithm, &mut reader, self.exp, self.aud, self.sub)?;
        println!("jwt token: {}", token);
        Ok(())
    }
}

impl CmdExecutor for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader: Box<dyn Read> = get_reader(&self.key)?;
        let token_data =
            process_jwt_verify(self.algorithm, &mut reader, self.token, self.aud, self.sub)?;
        println!("claims: {:?}", token_data.claims);
        println!("header: {:?}", token_data.header);
        Ok(())
    }
}
