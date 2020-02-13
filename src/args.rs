use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use structopt::StructOpt;

/// Encrypts/decrypts files using symmetric encryption plus some custom
/// data scrambling.
#[derive(Debug, StructOpt)]
pub struct GiopgArgs {
    /// The action to perform [encrypt|decrypt]
    pub action: Action,

    /// The input file
    #[structopt(parse(from_os_str))]
    pub input_file: PathBuf,

    /// The output file
    #[structopt(short = "o", long = "output", parse(from_os_str))]
    pub output_file: PathBuf,

    /// Asks for a passphrase interactively.
    /// If not specified, an empty passphrase will be used.
    #[structopt(short = "p", long = "passphrase")]
    pub passphrase: bool,
}

#[derive(Debug, StructOpt)]
pub enum Action {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionParseError {
    s: String,
}

impl Error for ActionParseError {}

impl fmt::Display for ActionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format!(
            "illegal value '{}' for Action (expected: encrypt|decrypt)",
            self.s
        )
        .fmt(f)
    }
}

impl FromStr for Action {
    type Err = ActionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "encrypt" => Ok(Action::Encrypt),
            "decrypt" => Ok(Action::Decrypt),
            _ => Err(ActionParseError { s: String::from(s) }),
        }
    }
}

pub fn parse_args() -> GiopgArgs {
    let args = GiopgArgs::from_args();
    info!("parsed giopg command line arguments: {:?}", args);
    args
}
