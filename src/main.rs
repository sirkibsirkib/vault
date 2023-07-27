extern crate crypto;
// extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate base64;
extern crate serde;
extern crate rand;
extern crate serde_json;
extern crate chrono;
extern crate rpassword;
extern crate fnv;

use fnv::FnvHashSet;
use rand::Rng;

use rpassword::read_password;

use bincode::{serialize, deserialize};

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io::{Error, ErrorKind};
use std::io::stdout;
use std::path::{Path, PathBuf};
use std::io::BufReader;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
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


// some string the user is very unlikely to want to use as a key
static KEYLIST_KEY: &'static str = "GYggF^DgiuhIUHiuf^&F7fHBVFCr";

// relevant for printing with `list`
const KEYS_PER_LINE: usize = 7;

// source: rust-crypto examples on github
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

// source: rust-crypto examples on github
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

// serializable structure representing a key's value entry/entries
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Secret {
	key: String,
	value: Vec<(DateTime<Local>, String)>,
	noise: Vec<u8>, // never used. just gives the secret some arbi
}

// prompts user password and generates the session key from it
fn get_session_key_from_user() -> Result<SessionKey, ()> {
	let mut iv = [0u8; 16];
	fill_with_ascending(&mut iv);

	let mut key = [0u8; 32];
	print!("Type a password: ");
	if stdout().flush().is_err() { return Err(()) }
	let password: String = read_password().unwrap();

	let mut hasher = Sha256::new();
	hasher.input_str(&password);
	hasher.input(&iv);
	hasher.input_str("OH_YEAH_SALT");
	hasher.result(&mut key[0..32]);
	let sanity = &base64::encode(&key[..2])[..3];
	println!("password sanity hash: {}", sanity);
	Ok(SessionKey{ key, iv })
}

// for generating padding
fn fill_with_ascending(v: &mut [u8]) {
	for (i, mut b) in v.iter_mut().enumerate() {
		*b = i as u8;
	}
}

// derived structure from user's password
struct SessionKey {
	key: [u8; 32],
	iv: [u8; 16],
}

// convenience function for reading stripped line
fn read_cleaned_stdin_line(s: &mut String) -> bool {
	s.clear();
	if let Ok(_bytes) = io::stdin().read_line(s) {
		let len_withoutcrlf = s.trim_right().len();
		s.truncate(len_withoutcrlf);
		true
	} else {
		false
	}
}

fn print_help() {
	println!("commands:
- list         prints all known keys
- filename     prints the filename associated with key x
- get <x>      reads and prints values for key x
- push <x> <y> appends value y to entry for key x
- pop <x>      pops the most recent value for key x
- rm <x>       removes the entire entry for key x
- ?            prints help");
}


// attempt to return the path to the desired persistent storage directory
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

fn get_list_manager<'a>(session_key: &'a SessionKey, store_path: &Path) -> ListManager<'a> {
	let mut pb = PathBuf::from(store_path);
	push_file_name_for(&mut pb, session_key, KEYLIST_KEY);
	if let Ok(kl) = get_persistent::<KeyList>(session_key, &pb) {
		ListManager::new_from(session_key, store_path, kl)
	} else {
		let kl = KeyList{ v: FnvHashSet::default() };
		println!("Warning: No existing key-list found. Is this your first session?");
		if write_persistent(session_key, &pb, &kl).is_err() {
			println!("Warning: Failed to write KeyList object.");
		}
		ListManager::new_from(session_key, store_path, kl)
	}
}

fn main() {
	let store_path = match get_store_path() {
		Ok(s) => s,
		Err(_) => { println!("Failed to read store path"); return; },
	};
	println!("store path {:?}", &store_path);
	let session_key = get_session_key_from_user()
	.expect("Failed to get session key");

	let mut lm = get_list_manager(&session_key, &store_path);
	println!("REPL started. Enter ? for help.");

	// REPL
	let mut cmd_input = String::new();
	loop {
		lm.write_if_changes(); //update list manager if necessary
		if !read_cleaned_stdin_line(&mut cmd_input) {
			panic!("Failed to read from stdin");
		}
		let tokens: Vec<&str> = cmd_input.split(" ").filter(|x| x.len() > 0).collect();
		if tokens.len() == 0 { continue }
		match &tokens[0] as &str {
			"?" => print_help(),
			"get" => {
				if tokens.len() == 2 {
					cmd_get(&session_key, tokens[1], &store_path, &mut lm);
				} else {
					println!("Expecting 2 tokens for {}", tokens[0]);
				}
			},
			"push" => {
				if tokens.len() == 3 {
					cmd_push(&session_key, tokens[1], tokens[2], &store_path, &mut lm);
				} else {
					println!("Expecting 3 tokens for {}", tokens[0]);
				}
			},
			"pop" => {
				if tokens.len() == 2 {
					cmd_pop(&session_key, tokens[1], &store_path, &mut lm);
				} else {
					println!("Expecting 2 tokens for {}", tokens[0]);
				}
			},
			"rm" => {
				if tokens.len() == 2 {
					cmd_rm(&session_key, tokens[1], &store_path, &mut lm);
				} else {
					println!("Expecting 2 tokens for {}", tokens[0]);
				}
			},
			"list" => {
				if tokens.len() == 1 {
					lm.print_keys();
				} else {
					println!("Expecting 1 token for {}", tokens[0]);
				}
			},
			"filename" => {
				if tokens.len() == 2 {
					println!("{}", filename_for(&session_key, tokens[1]));
				} else {
					println!("Expecting 2 token for {}", tokens[0]);
				}
			},
			_ => {println!("Unknown command. Enter ? for help.");}
		}
	}
}

// determine the (hashed) filename with the given (value) key and session_key
fn filename_for(session_key: &SessionKey, key: &str) -> String {
	let mut hasher = Sha256::new();
	hasher.input(&session_key.key);
	hasher.input_str(&key);
	hasher.input_str("SALTY_POTATOES");
	let mut hash_buffer = [0u8; 32];
	hasher.result(&mut hash_buffer[0..32]);
	base64::encode(&hash_buffer).replace("/", "$")
}

// `filename_for` result appended to the given pathbuf
fn push_file_name_for(pb: &mut PathBuf, session_key: &SessionKey, key: &str) {
	pb.push(filename_for(session_key, key));
}

// queries for user's confirmation and returns result. Used for checking risky actions.
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

// user gave command `push <key> <value>`
fn cmd_push(session_key: &SessionKey, key: &str, value: &str, store_path: &Path, lm: &mut ListManager) {
	let mut pb = PathBuf::from(store_path);
	let filename = filename_for(session_key, key); 
	pb.push(&filename);
	let secret = if let Ok(mut secret) = get_persistent::<Secret>(session_key, &pb) {
		// read from existing key-value file and modify it.
		if secret.key != key &&
		!user_confirmation(&key_warning(&secret.key)) {
			lm.key_doesnt_exist(key);
			return
		}
		secret.value.push((Local::now(), value.to_owned()));
		secret
	} else {
		// create a new key-value file.
		let noise_length: usize = rand::thread_rng().gen_range(0, 128);
		Secret {
			key: key.to_owned(),
			value: vec![
				(Local::now(), value.to_owned())
			],
			noise: filename.as_bytes().iter().cloned()
				.cycle().take(noise_length).collect(),
		}	
	};
	lm.key_exists(key);
	// write the changed/new key-value file back to persistent storage
	if let Err(e) = write_persistent(session_key, &pb, &secret) {
		println!("Error: {:?}", e);
	}
}

// user gave command `rm <key>`
fn cmd_rm(session_key: &SessionKey, key: &str, store_path: &Path, lm: &mut ListManager) {
	let mut pb = PathBuf::from(store_path);
	push_file_name_for(&mut pb, session_key, key);
	if pb.exists() {
		if let Ok(secret) = get_persistent::<Secret>(session_key, &pb) {
			lm.key_exists(key);
			if secret.key != key &&
			!user_confirmation(&key_warning(&secret.key)) {
				return
			}
			if !user_confirmation(&format!(
					"Are you certain you want to delete this key with {} entries?",
					secret.value.len(),
				)) {
				return
			}
		} else  {
			lm.key_doesnt_exist(key);
			if !user_confirmation("Found entry file, but cannot open it using current config. Proceed with rm?") {
				return
			}
		};
		if let Err(e) = fs::remove_file(&pb) {
			println!("Error {:?}", e);
		} else {
			lm.key_doesnt_exist(key);
		}
	} else {
		lm.key_doesnt_exist(key);
		println!("Failed to find entry file.");
	}
}

// user gave command `pop <key>`
fn cmd_pop(session_key: &SessionKey, key: &str, store_path: &Path, lm: &mut ListManager) {
	let mut pb = PathBuf::from(store_path);
	push_file_name_for(&mut pb, session_key, key);
	if let Ok(mut secret) = get_persistent::<Secret>(session_key, &pb) {
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
			lm.key_exists(key);
			return;
		}
		let before = secret.value.len();
		secret.value.pop();
		println!("number of secret values {}->{}", before, secret.value.len());
		if let Err(e) = write_persistent(session_key, &pb, &secret) {
			println!("Error: {:?}", e);
		}
	} else {
		lm.key_doesnt_exist(key);
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

// user gave command `get <key>`
fn cmd_get(session_key: &SessionKey, key: &str, store_path: &Path, lm: &mut ListManager) {
	let mut pb = PathBuf::from(store_path);
	push_file_name_for(&mut pb, session_key, key);
	match get_persistent::<Secret>(session_key, &pb) {
		Ok(secret) => {
			lm.key_exists(key);
			if secret.key != key &&
			!user_confirmation(&key_warning(&secret.key)) {
				return
			}
			println!("key: {}", secret.key);
			for (i, value) in secret.value.iter().enumerate() {
				println!("{:>6} | {} | {}", i, &value.0.format("%F %T"), value.1);
			}
			if secret.value.is_empty() {
				println!("  <no values>");
			}
		},
		Err(e) => {
			let msg = match e.kind() {
				ErrorKind::Other => "Failed to deserialize data.",
				ErrorKind::InvalidData => "Failed to decrypt data.",
				_ => "Failed to open file."
			};
			println!("{}", msg);
		},
	}
}

// serializes, encrypts and writes a secret/list object to persistent storage
fn write_persistent<T:Serialize>(session_key: &SessionKey, file_path: &Path, t: &T) -> Result<(), std::io::Error> {
	let mut file = File::create(file_path)?;
	let payload_bytes = &serialize(&t).expect("Failed to serialize");
	let encrypted_data = encrypt(payload_bytes, &session_key.key, &session_key.iv).ok().unwrap();
	file.write_all(&encrypted_data)?;
	Ok(())
}

// reads, decrypts and deserializes a secret/list object from persistent storage
fn get_persistent<T:DeserializeOwned>(session_key: &SessionKey, file_path: &Path) -> Result<T, std::io::Error> {
	let file = File::open(file_path)?;
	let mut buf_reader = BufReader::new(file);
	let mut buf = vec![];
	buf_reader.read_to_end(&mut buf)?;
	if let Ok(decrypted_data) = decrypt(&buf, &session_key.key, &session_key.iv) {
		return deserialize(&decrypted_data).map_err(
			|_| Error::new(ErrorKind::Other, "bincode")
		)
	}
	Err(Error::new(ErrorKind::InvalidData, "aes"))
}

// inner structure for a list of known keys. Treated as data.
#[derive(Debug, Serialize, Deserialize)]
struct KeyList {
	v: FnvHashSet<String>,
}

// outer structure for a list of known keys. Includes fields that are not included in persistent storage
struct ListManager<'a> {
	kl: KeyList,
	pb: PathBuf,
	session_key: &'a SessionKey,
	changes: bool,
}

impl<'a> ListManager<'a> {
	fn new_from(session_key: &'a SessionKey, store_path: &Path, kl: KeyList) -> Self {
		let mut pb = PathBuf::from(store_path);
		push_file_name_for(&mut pb, session_key, KEYLIST_KEY);
		Self { kl, pb, session_key, changes: false }
	}

	fn key_exists(&mut self, key: &str) {
		if !self.kl.v.contains(key) {
			self.kl.v.insert(key.to_owned());
			self.changes = true;
		}
	}
	fn key_doesnt_exist(&mut self, key: &str) {
		if self.kl.v.contains(key) {
			self.kl.v.remove(key);
			self.changes = true;
		}
	}
	fn write_if_changes(&mut self) {
		if self.changes {
			if write_persistent(self.session_key, &self.pb, &self.kl).is_err() {
				println!("Warning: Failed to write KeyList object.");
			}
			self.changes = false;
		}
	}
	fn print_keys(&self) {
		print!("known keys: ");
		let comma_index = self.kl.v.len()-1;
		for (i, key) in self.kl.v.iter().enumerate() {
			if i%KEYS_PER_LINE==0 { println!() }
			print!("{}", key);
			if i < comma_index {
				print!(", ")
			}
		}
		println!();
	}
}
