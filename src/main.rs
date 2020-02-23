#[macro_use]
extern crate log;

use human_panic::setup_panic;
use log::LevelFilter;
use log4rs;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use rpassword;
use sodiumoxide;
use std::error::Error;
use std::fs::File;

use args::Action;

mod args;
mod secretbox;

fn main() -> Result<(), Box<dyn Error>> {
    setup_panic!();
    init_log();
    sodiumoxide::init().expect("sodiumoxide initialization failed");

    let args = args::parse_args();

    let action = args.action;
    let mut input_file = File::open(args.input_file)?;
    let mut output_file = File::create(args.output_file)?;
    let passphrase = args.passphrase;

    let passphrase_string = match passphrase {
        false => String::from(""),
        true => rpassword::read_password_from_tty(Some("Passphrase: "))?,
    };

    match action {
        Action::Encrypt => secretbox::encrypt(
            passphrase_string.as_str(),
            &mut input_file,
            &mut output_file,
        )?,
        Action::Decrypt => secretbox::decrypt(
            passphrase_string.as_str(),
            &mut input_file,
            &mut output_file,
        )?,
    }

    Ok(())
}

fn init_log() {
    let stdout = ConsoleAppender::builder().build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .logger(Logger::builder().build("giopg::secretbox", LevelFilter::Debug))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        .unwrap();

    log4rs::init_config(config).unwrap();
}
