extern crate crypto;
extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate base64;
extern crate serde_json;
extern crate chrono;
extern crate rpassword;

use rpassword::read_password;

use bincode::{serialize, deserialize};

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io::{Error, ErrorKind};
use std::io::stdout;
use std::path::{Path, PathBuf};
use rand::RngCore;
use std::io::BufReader;
use std::fs::{
	self,
	File,
};
use chrono::prelude::*;

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
	value: Vec<(DateTime<Local>, String)>,
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

fn get_store_path() -> Result<PathBuf, std::io::Error> {
	if let Some(arg) = std::env::args().nth(1) {
		// 1st choice: user provided location as argument
		return Ok(PathBuf::from(arg));
	}
	
	// 2nd choice. Try find a "config.json" at same path as this binary
	let config_file = {
		let mut p = PathBuf::from(std::env::args().nth(0).unwrap());
		p.pop();
		p.push("config.json");
		File::open(&p)?
	};
    let mut buf_reader = BufReader::new(config_file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;
    let v: serde_json::Value = serde_json::from_str(&contents)?;
    if let Some(Some(s)) = v.get("store_path").map(|x| x.as_str()) {
    	return Ok(PathBuf::from(s))
    }
    Err(Error::new(ErrorKind::Other, "oh no!"))
}

fn main() {
	let store_path = get_store_path().expect("Failed to read store path");
	println!("store path {:?}", &store_path);
    let session_key = get_session_key_from_user()
    .expect("Failed to get session key");
    println!("REPL started. Enter `?` for help.");

    let mut cmd_input = String::new();
    loop {
    	if !read_cleaned_stdin_line(&mut cmd_input) {
    		panic!("Failed to read from stdin");
    	}
    	let tokens: Vec<&str> = cmd_input.split(" ").filter(|x| x.len() > 0).collect();
    	if tokens.len() == 0 {continue}
    	match &tokens[0] as &str {
    		"?" => print_help(),
    		"get" => {
    			if tokens.len() == 2 {
    				cmd_get(&session_key, tokens[1], &store_path);
    			} else {
    				println!("Expecting 2 tokens for `{}`", tokens[0]);
    			}
    		},
    		"push" => {
    			if tokens.len() == 3 {
    				cmd_push(&session_key, tokens[1], tokens[2], &store_path);
    			} else {
    				println!("Expecting 3 tokens for `{}`", tokens[0]);
    			}
    		},
    		"pop" => {
    			if tokens.len() == 2 {
    				cmd_pop(&session_key, tokens[1], &store_path);
    			} else {
    				println!("Expecting 2 tokens for `{}`", tokens[0]);
    			}
    		}

    		_ => {println!("Unknown command. Enter `?` for help.");}
    	}
    }
}

fn push_file_name_for(pb: &mut PathBuf, session_key: &SessionKey, key: &str) {
	let mut hasher = Sha256::new();
	hasher.input(&session_key.key);
	hasher.input_str(&key);
	hasher.input_str("SALTY_POTATOES");
	let mut hash_buffer = [0u8; 32];
	hasher.result(&mut hash_buffer[0..32]);
	pb.push( base64::encode(&hash_buffer).replace("/", "$"));
}

fn user_confirmation(msg: &str) -> bool {
	let mut s = String::new();
	println!("{} (y/n)", msg);
	if read_cleaned_stdin_line(&mut s) {
		match &s as &str {
			"y" => return true,
			_ => (),
		}
	}
	println!("aborted.");
	false
}

fn cmd_push(session_key: &SessionKey, key: &str, value: &str, store_path: &Path) {
	let mut pb = PathBuf::from(store_path);
	push_file_name_for(&mut pb, session_key, key);
	let secret = if let Ok(mut secret) = get_secret_object(session_key, &pb) {
		if secret.key != key &&
		!user_confirmation(&key_warning(&secret.key)) {
			return
		}
		secret.value.push((Local::now(), value.to_owned()));
		secret
	} else {
		if !pb.exists() && !user_confirmation("No existing entry found. Push to new entry?") {
			return;
		}
		Secret {
			key: key.to_owned(),
			value: vec![
				(Local::now(), value.to_owned())
			]
		}	
	};
	if let Err(e) = write_secret_object(session_key, &pb, &secret) {
		println!("Error: {:?}", e);
	}
}

fn cmd_pop(session_key: &SessionKey, key: &str, store_path: &Path) {
	let mut pb = PathBuf::from(store_path);
	push_file_name_for(&mut pb, session_key, key);
	if let Ok(mut secret) = get_secret_object(session_key, &pb) {
		if secret.key != key &&
		!user_confirmation(&key_warning(&secret.key)) {
			return
		}
		if secret.value.len() == 0 {
			return;
		}
		let to_rem = secret.value.last().unwrap().clone();
		if !user_confirmation(
			&format!(
				"Are you certain you wish to remove ({} | {} | {})",
				secret.value.len()-1,
				&to_rem.0.format("%F %T"),
				to_rem.1,
			)
		) {
			return;
		}
		let before = secret.value.len();
		secret.value.pop();
		println!("number of secret values {}->{}", before, secret.value.len());
		if let Err(e) = write_secret_object(session_key, &pb, &secret) {
			println!("Error: {:?}", e);
		}
	} else {
		println!("Entry not found.");
		return
	}
	
}

fn key_warning(found: &str) -> String {
	format!(
		"Found unexpected key in loaded secret: {:?}. Continue?",
		found,
	)
}

fn cmd_get(session_key: &SessionKey, key: &str, store_path: &Path) {
	let mut pb = PathBuf::from(store_path);
	push_file_name_for(&mut pb, session_key, key);
	match get_secret_object(session_key, &pb) {
		Ok(secret) => {
			if secret.key != key &&
			!user_confirmation(&key_warning(&secret.key)) {
				return
			}
			println!("key: `{}`", secret.key);
			for (i, value) in secret.value.iter().enumerate() {
				println!("{:>6} | {} | `{}`", i, &value.0.format("%F %T"), value.1);
			}
			if secret.value.is_empty() {
				println!("  <no values>");
			}
		},
		Err(e) => println!("NAH {:?}", e),
	}
}

fn write_secret_object(session_key: &SessionKey, file_path: &Path, secret: &Secret) -> Result<(), std::io::Error> {
	let mut file = File::create(file_path)?;
	let payload_bytes = &serialize(&secret).expect("Failed to serialize");
    let encrypted_data = encrypt(payload_bytes, &session_key.key, &session_key.iv).ok().unwrap();
    file.write_all(&encrypted_data)?;
    Ok(())
}


fn get_secret_object(session_key: &SessionKey, file_path: &Path) -> Result<Secret, std::io::Error> {
	let file = File::open(file_path)?;
    let mut buf_reader = BufReader::new(file);
    let mut buf = vec![];
    buf_reader.read_to_end(&mut buf)?;
    if let Ok(decrypted_data) = decrypt(&buf, &session_key.key, &session_key.iv) {
    	return deserialize(&decrypted_data).map_err(
    		|_| Error::new(ErrorKind::Other, "Bincode deserialize failed")
    	)
    }
    Err(Error::new(ErrorKind::Other, "Failed to decrypt that file"))
}