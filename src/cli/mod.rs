mod base64;
mod csv;
mod genpass;

use std::path::Path;

use clap::Parser;

pub use base64::{Base64Format, Base64SubCommand};
pub use csv::OutputFormat;

use self::csv::CsvOpts;
use self::genpass::GenPassOpts;

#[derive(Debug, Parser)]
#[command(name="rcli", version, author, about, long_about=None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV or convert CSV to other formats")]
    Csv(CsvOpts),

    #[command(name = "genpass", about = "Generate a password")]
    GenPass(GenPassOpts),

    #[command(subcommand)]
    Base64(Base64SubCommand),
}

fn parse_input_file(filename: &str) -> Result<String, &'static str> {
    // if input is "-" or file exists, return the filename
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
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
