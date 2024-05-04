mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;

use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::path::{Path, PathBuf};

pub use self::{base64::*, csv::*, genpass::*, http::*, jwt::*, text::*};

#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert CSV to other formats")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand, about = "Base64 encode/decode")]
    Base64(Base64SubCommand),
    #[command(subcommand, about = "Text sign/verify")]
    Text(TextSubCommand),
    #[command(subcommand, about = "HTTP server")]
    Http(HttpSubCommand),
    #[command(subcommand, about = "Sign and verify json web token")]
    Jwt(JwtSubCommand),
}

fn parse_input_file(filename: &str) -> Result<String, &'static str> {
    // if input is "-" or file exists, return the filename
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

fn parse_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_input_file() {
        assert_eq!(parse_input_file("-"), Ok("-".into()));
        assert_eq!(parse_input_file("*"), Err("File does not exist"));
        assert_eq!(parse_input_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(parse_input_file("not-exist"), Err("File does not exist"));
    }
}
