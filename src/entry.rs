use std::collections::HashMap;
use std::fs::{File, remove_file};
use std::io::{Read, Write};
use std::num::NonZeroU32;
use aes_gcm::{AeadCore, Aes256Gcm, AesGcm, Key, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use anyhow::{anyhow, Result};

struct Entry {
    name: String,
    username: String,
    email: String,
    password: String
}

impl Entry {
    fn new() -> Self {
        Self {
            name: "".to_string(),
            username: "".to_string(),
            email: "".to_string(),
            password: "".to_string()
        }
    }
}

fn encrypt(cipher: &AesGcm<Aes256, U12>, entry_data: &String, file: &mut File) -> Result<()> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    match cipher.encrypt(&nonce, entry_data.as_ref()) {
        Ok(cipher_text) => {
            let mut data_to_write = Vec::new();
            data_to_write.extend_from_slice(nonce.as_ref());
            data_to_write.extend_from_slice(cipher_text.as_ref());

            file.write_all(&data_to_write)?;
        }
        Err(_) => return Err(anyhow!("Invalid data!"))
    }
    Ok(())
}

pub(crate) fn add_entry(password: &String, mut name: String) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("Invalid input!"));
    }

    name.push_str(".pass");
    let mut entry = Entry::new();
    entry.name = name;

    println!("Press Enter to leave it empty");
    println!("username:");
    std::io::stdin().read_line(&mut entry.username)?;
    println!("email:");
    std::io::stdin().read_line(&mut entry.email)?;
    println!("password:");
    std::io::stdin().read_line(&mut entry.password)?;

    if entry.username.trim() == "" && entry.email.trim() == "" && entry.password.trim() == "" {
        return Err(anyhow!("Invalid input!"));
    }

    let mut file = File::create(&entry.name)?;

    let mut config_file = File::open("config.pass")?;
    let mut from_file = Vec::new();

    config_file.read_to_end(&mut from_file)?;
    let salt = &from_file[12..24];
    let mut key_rand = from_file[24..56].to_vec();

    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), salt.as_ref(), password.as_bytes(), &mut key_rand);

    let key = Key::<Aes256Gcm>::from_slice(&key_rand);
    let cipher = Aes256Gcm::new(&key);

    let mut data = String::new();
    data.push_str(&entry.username);
    data.push_str(&entry.email);
    data.push_str(&entry.password);
    encrypt(&cipher, &data, &mut file)?;
    file.flush()?;
    Ok(())
}

pub(crate) fn remove_entry(mut name: String) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("Invalid input!"));
    }

    name.push_str(".pass");
    remove_file(&name)?;
    Ok(())
}

fn decrypt(cipher: &AesGcm<Aes256, U12>, encrypted_text: &Vec<u8>, out: &mut String) -> Result<()> {
    let nonce= &encrypted_text[0..12];
    let nonce = aes_gcm::Nonce::from_slice(&nonce);
    let cipher_text = encrypted_text[12..].to_vec();

    match cipher.decrypt(&nonce, cipher_text.as_ref()){
        Ok(plain_text) => { *out = String::from_utf8(plain_text).unwrap().to_string(); }
        Err(err) => {println!("Failed to decrypt: {}", err)}
    }

    Ok(())
}

pub(crate) fn get_entry(password: &String, mut name: String) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("Invalid input!"));
    }

    name.push_str(".pass");
    let mut entry = Entry::new();
    entry.name = name;

    let mut file = File::open("config.pass")?;
    let mut from_file = Vec::new();

    file.read_to_end(&mut from_file)?;
    let salt = &from_file[12..24];
    let mut key_rand = from_file[24..56].to_vec();

    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), salt.as_ref(), password.as_bytes(), &mut key_rand);
    let key = Key::<Aes256Gcm>::from_slice(&key_rand);
    let cipher = Aes256Gcm::new(&key);

    let mut file = File::open(&entry.name)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let mut data_str = String::new();
    decrypt(&cipher, &data, &mut data_str)?;

    print!("    username: ");
    let map = HashMap::from([(0, "    username: "), (1, "    email: "), (2, "    password: ")]);
    let mut index = 0;
    for element in data_str.chars() {
        if element == '\n' {
            index += 1;
            println!();
            if index < 3 {
                print!("{}", map[&{index}]);
            }
            continue;
        };
        print!("{element}");
    }
    Ok(())
}
