extern crate crypto;
extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate base64;
extern crate rpassword;

use rpassword::read_password;

use bincode::{serialize, deserialize};

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io::stdout;
use std::path::{Path, PathBuf};
use rand::RngCore;

use std::io::{
	self,
	Read,
	Write,
};
use rand::{Rng, SeedableRng, StdRng, OsRng};

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Secret {
	key: String,
	value: Vec<String>,
}

fn get_session_key_from_user() -> Result<SessionKey, ()> {
    let mut key: [u8; 32] = [0; 32];
    fill_with_ascending(&mut key);
    print!("Type a password: ");
	stdout().flush();

    let password: String = read_password().unwrap();
    println!("\rThe password is: '{}'", password);

	let password_bytes = password.trim_right().as_bytes();
	if password_bytes.len() > 32 {
		println!("TOO MANY");
		return Err(())
	}
	for (i, b) in password_bytes.iter().cloned().take(32).enumerate() {
		key[i] = b;
	}
    let mut iv = [0u8; 16];
    fill_with_ascending(&mut iv);
    Ok(SessionKey{ key, iv })
}

fn fill_with_ascending(v: &mut [u8]) {
	for (i, mut b) in v.iter_mut().enumerate() {
		*b = i as u8;
	}
}

fn path_for(key: &str) -> PathBuf {
	let mut path = PathBuf::new();
	path.push("key");
	path
}

struct SessionKey {
	key: [u8; 32],
	iv: [u8; 16],
}

fn read_cleaned_stdin_line(s: &mut String) -> bool {
	s.clear();
	if let Ok(b) = io::stdin().read_line(s) {
	    let len_withoutcrlf = s.trim_right().len();
	    s.truncate(len_withoutcrlf);
	    true
	} else {
		false
	}
}

fn print_help() {
	println!("HELPY HELPY HELP");
}

fn main() {
    // step 1: get user session keys
    let session_key = get_session_key_from_user()
    .expect("Failed to get session key");
    println!("REPL started. Enter `?` for help.");

    let mut cmd_input = String::new();
    loop {
    	if !read_cleaned_stdin_line(&mut cmd_input) {
    		panic!("Failed to read from stdin");
    	}
    	let tokens: Vec<&str> = cmd_input.split(" ").collect();
    	if tokens.len() == 0 {continue}
    	match &tokens[0] as &str {
    		"?" => print_help(),
    		"get" => {
    			if tokens.len() < 2 {
    				println!("Expecting 2 tokens for `get`");
    			} else {
    				cmd_get(&session_key, tokens[1]);
    			}
    		},
    		_ => {println!("Unknown command. Enter `?` for help.");}
    	}
    }
}

fn cmd_get(session_key: &SessionKey, key: &str) {
	println!("GETTTTY");
}

fn bogus() {
 //    let payload = Secret {key:"Dank".to_owned(), value:vec!["Memes".to_owned()]};
	// let mut hasher = Sha256::new();
	// hasher.input_str(&payload.key);
	// hasher.input(&key);
	// hasher.input(&iv);
	// let mut hash_buffer = [0u8; 32];
	// hasher.result(&mut hash_buffer[0..32]);
	// let b64_hash = base64::encode(&hash_buffer);
	// println!("key hashes to {:?}", &b64_hash);

	// let payload_bytes = &serialize(&payload).expect("Failed to serialize");

 //    let encrypted_data = encrypt(payload_bytes, &key, &iv).ok().unwrap();
 //    println!("enc {:?}", &encrypted_data);

 //    let decrypted_data = &decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();
 //    println!("dec {:?}", &decrypted_data);
 //    let payload2 = deserialize(&decrypted_data).expect("Failed to deserialize");
 //    println!("payload2 {:?}", &payload2);

 //    assert!(payload == payload2);
}