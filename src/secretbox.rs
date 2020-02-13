use std::error::Error;
use std::fmt;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Key;
use sodiumoxide::crypto::secretbox::Nonce;
use std::io::{Read, Write};

pub fn encrypt(
    passphrase: &str,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
    scrambler::write_random_bytes(output, scrambler::PREFIX_LENGTH)?;

    let encrypted_buf = {
        let mut content = Vec::new();
        scrambler::write_random_bytes(&mut content, scrambler::ENCRYPT_PREFIX_LENGTH)?;
        input.read_to_end(&mut content)?;
        scrambler::write_random_bytes(&mut content, scrambler::ENCRYPT_SUFFIX_LENGTH)?;

        let nonce = build_nonce();
        let key = build_key(passphrase);
        secretbox::seal(&content[..], &nonce, &key)
    };

    let re_encrypted_buf = {
        let alternate_nonce = build_alternate_nonce();
        let alternate_key = build_alternate_key(passphrase);
        secretbox::seal(&encrypted_buf[..], &alternate_nonce, &alternate_key)
    };

    debug!("input successfully encrypted");
    output.write_all(&re_encrypted_buf)?;
    debug!("encrypted input successfully written to output");
    Ok(())
}

pub fn decrypt(
    passphrase: &str,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
    scrambler::strip_random_bytes(input, scrambler::PREFIX_LENGTH)?;

    let decrypted_buf = {
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;

        let alternate_nonce = build_alternate_nonce();
        let alternate_key = build_alternate_key(passphrase);
        let open_res = secretbox::open(&content[..], &alternate_nonce, &alternate_key);

        match open_res {
            Ok(decrypted_buf) => decrypted_buf,
            Err(_) => return Err(Box::new(DecryptError {})),
        }
    };

    let re_decrypted_buf = {
        let nonce = build_nonce();
        let key = build_key(passphrase);
        let open_res = secretbox::open(&decrypted_buf[..], &nonce, &key);
        match open_res {
            Ok(decrypted_buf) => decrypted_buf,
            Err(_) => return Err(Box::new(DecryptError {})),
        }
    };

    debug!("input successfully decrypted");
    let start_idx = scrambler::ENCRYPT_PREFIX_LENGTH;
    let end_idx = re_decrypted_buf.len() - scrambler::ENCRYPT_SUFFIX_LENGTH;
    output.write_all(&re_decrypted_buf[start_idx..end_idx])?;
    debug!("decrypted input successfully written to output");

    Ok(())
}

fn build_nonce() -> Nonce {
    // init nonce bytes
    let mut nonce: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
    for i in 0..nonce.len() {
        nonce[i] = (i + 21) as u8;
    }
    Nonce(nonce)
}

fn build_alternate_nonce() -> Nonce {
    // init nonce bytes
    let mut nonce: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
    for i in 0..nonce.len() {
        nonce[nonce.len() - 1 - i] = (i + 13) as u8;
    }
    Nonce(nonce)
}

fn build_key(passphrase: &str) -> Key {
    let mut passphrase = String::from(passphrase);
    passphrase.push_str("Y@S6BdQd!&9mBEXfW&#65gJyy");

    // init key bytes
    let mut key: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
    for i in 0..key.len() {
        key[i] = (i + 19) as u8;
    }

    // apply string on key bytes
    let s_bytes = &passphrase.as_bytes();
    for i in 0..secretbox::KEYBYTES {
        if i < passphrase.len() {
            key[i] = s_bytes[i];
        }
    }

    Key(key)
}

fn build_alternate_key(passphrase: &str) -> Key {
    let mut passphrase = String::from(passphrase);
    passphrase.push_str("E2f&@DKXW*wtd43d!&@M^JLqD");

    // init key bytes
    let mut key: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
    for i in 0..key.len() {
        key[i] = (i + 23) as u8;
    }

    // apply string on key bytes
    let s_bytes = &passphrase.as_bytes();
    for i in 0..secretbox::KEYBYTES {
        if i < passphrase.len() {
            key[i] = s_bytes[i];
        }
    }

    Key(key)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptError {}

impl Error for DecryptError {}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "decrypt error".fmt(f)
    }
}

mod scrambler {
    use sodiumoxide::randombytes;
    use std::error::Error;
    use std::io::{Read, Write};
    
    pub const PREFIX_LENGTH: usize = 231;
    pub const ENCRYPT_PREFIX_LENGTH: usize = 147;
    pub const ENCRYPT_SUFFIX_LENGTH: usize = 31;

    /// Write n random bytes to the specified writer
    pub fn write_random_bytes(writer: &mut dyn Write, n: usize) -> Result<(), Box<dyn Error>> {
        let buf = randombytes::randombytes(n);
        writer.write_all(buf.as_slice())?;
        Ok(())
    }

    /// Strip n random bytes from the specified reader
    pub fn strip_random_bytes(reader: &mut dyn Read, n: usize) -> Result<(), Box<dyn Error>> {
        let mut v = Vec::new();
        let mut reader_limit = reader.take(n as u64);
        reader_limit.read_to_end(&mut v)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn test_encrypt_decrypt() -> Result<(), Box<dyn Error>> {
        sodiumoxide::init().expect("sodiumoxide initialization failed");

        let passphrase = "My_P4ssPhr4s3_Str1ng";
        let msg = "My secret content";

        let mut enc_input = BufReader::new(msg.as_bytes());
        let mut enc_output: Vec<u8> = Vec::new();
        encrypt(passphrase, &mut enc_input, &mut enc_output)?;

        let mut dec_input = BufReader::new(enc_output.as_slice());
        let mut dec_output = Vec::new();
        let dec_result = decrypt(passphrase, &mut dec_input, &mut dec_output);

        match dec_result {
            Ok(_) => assert_eq!(dec_output, msg.as_bytes()),
            Err(err) => panic!("decrypt failed: {:?}", err),
        }

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_long_message() -> Result<(), Box<dyn Error>> {
        sodiumoxide::init().expect("sodiumoxide initialization failed");

        let passphrase = "My_P4ssPhr4s3_Str1ng";
        let msg = "Ab".repeat(15 * 1024);

        let mut enc_input = BufReader::new(msg.as_bytes());
        let mut enc_output: Vec<u8> = Vec::new();
        encrypt(passphrase, &mut enc_input, &mut enc_output)?;

        let mut dec_input = BufReader::new(enc_output.as_slice());
        let mut dec_output = Vec::new();
        let dec_result = decrypt(passphrase, &mut dec_input, &mut dec_output);

        match dec_result {
            Ok(_) => assert_eq!(dec_output, msg.as_bytes()),
            Err(err) => panic!("decrypt failed: {:?}", err),
        }

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_wrong_decryption_passphrase() -> Result<(), Box<dyn Error>> {
        sodiumoxide::init().expect("sodiumoxide initialization failed");

        let passphrase = "My_P4ssPhr4s3_Str1ng";
        let msg = "My secret content";

        let wrong_passphrase = "Blah";

        let mut enc_input = BufReader::new(msg.as_bytes());
        let mut enc_output: Vec<u8> = Vec::new();
        encrypt(passphrase, &mut enc_input, &mut enc_output)?;

        let mut dec_input = BufReader::new(enc_output.as_slice());
        let mut dec_output = Vec::new();
        let dec_result = decrypt(wrong_passphrase, &mut dec_input, &mut dec_output);

        match dec_result {
            Ok(_) => panic!("decrypt should fail with wrong passphrase"),
            Err(_) => (),
        }

        Ok(())
    }
}
