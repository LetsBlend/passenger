use std::ffi::OsStr;
use std::fs::{File};
use std::io::{Read, Write};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use rand::random;
use std::num::NonZeroU32;
use std::path::PathBuf;
use aes_gcm::aead::{Aead, OsRng};
use anyhow::{anyhow};

pub(crate) fn signup(password: &String) -> anyhow::Result<()> {
    if password.is_empty() {
        return Err(anyhow!("Invalid input!"));
    }

    let path = std::path::Path::new("config.pass");
    if path.exists() {
        return Err(anyhow!("You already have an account!"));
    }

    // Data to check if password is correct in the future
    let text = String::from("ksadj/f023j4k-.asd#+21rfrawsf$j23*234ds#fs%dklvyl{k2)13++#123-2DS7dfgafdsg,s.sa2312f45d\"g65fga4!32?43rth+0#54d6%45a3mwa");

    // Per user
    let salt: [u8; 12] = random();

    let mut key_rand: [u8; 32] = random();
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), salt.as_ref(), password.as_bytes(), &mut key_rand);

    let key = Key::<Aes256Gcm>::from_slice(&key_rand);

    let cipher = Aes256Gcm::new(&key);

    // Per encryption
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    match cipher.encrypt(&nonce, text.as_ref()) {
        Ok(cipher_text) => {
            let mut data_to_write = Vec::new();
            data_to_write.extend_from_slice(nonce.as_ref());
            data_to_write.extend_from_slice(salt.as_ref());
            data_to_write.extend_from_slice(key_rand.as_ref());
            data_to_write.extend_from_slice(cipher_text.as_ref());

            let mut file =  File::create("config.pass")?;
            file.write_all(&data_to_write)?;
            file.flush()?;
        }
        Err(_) => return Err(anyhow!("Invalid data!"))
    }

    Ok(())
}

pub(crate) fn login(password: &String) -> anyhow::Result<()> {
    // Read
    let mut file = File::open("config.pass")?;
    let mut from_file = Vec::new();

    file.read_to_end(&mut from_file)?;
    let nonce= &from_file[0..12];
    let nonce = aes_gcm::Nonce::from_slice(&nonce);
    let salt = &from_file[12..24];
    let mut key_rand = from_file[24..56].to_vec();
    let cipher_text: Vec<u8> = from_file[56..].to_vec();

    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), salt.as_ref(), password.as_bytes(), &mut key_rand);
    let key = Key::<Aes256Gcm>::from_slice(&key_rand);
    let cipher = Aes256Gcm::new(&key);

    if let Ok(_) = cipher.decrypt(&nonce, cipher_text.as_ref()){
        return Ok(())
    }

    Err(anyhow!("Invalid password!"))
}

fn get_passenger_files() -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir("./").unwrap().filter_map(|result| result.ok()).map(|dir| dir.path()).filter_map(|path| {
        if path.extension().map_or(false, |ext| ext == "pass") {
            Some(path)
        } else {
            None
        }
    })
}

fn decrypt(password: &String) -> anyhow::Result<Vec<String>> {

    let mut file = File::open("config.pass")?;
    let mut from_file = Vec::new();

    file.read_to_end(&mut from_file)?;
    let salt = &from_file[12..24];
    let mut key_rand = from_file[24..56].to_vec();

    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), salt.as_ref(), password.as_bytes(), &mut key_rand);
    let key = Key::<Aes256Gcm>::from_slice(&key_rand);
    let cipher = Aes256Gcm::new(&key);

    let mut out = Vec::new();

    let entries = get_passenger_files();

    for entry in entries {
        let mut cipher_text_start = 12;
        let path = entry.as_path();
        if let Some(name) = path.file_name() {
            if name == OsStr::new("config.pass") {
                cipher_text_start = 56;
            }
        }

        let mut file = File::open(path)?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let nonce = &data[0..12];
        let nonce = aes_gcm::Nonce::from_slice(&nonce);
        let cipher_text = data[cipher_text_start..].to_vec();

        match cipher.decrypt(&nonce, cipher_text.as_ref()){
            Ok(plain_text) => { out.push(String::from_utf8(plain_text).unwrap().to_string()); }
            Err(err) => { return Err(anyhow!("Failed to decrypt: {}", err)); }
        }
    }

    Ok(out)
}

fn encrypt(new_password: &String, data: &Vec<String>) -> anyhow::Result<()> {
    // Per user
    let salt: [u8; 12] = random();

    let mut key_rand: [u8; 32] = random();
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), salt.as_ref(), new_password.as_bytes(), &mut key_rand);

    let key = Key::<Aes256Gcm>::from_slice(&key_rand);

    let cipher = Aes256Gcm::new(&key);

    let entries = get_passenger_files();

    for (index, entry) in entries.enumerate() {
        // Per encryption
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        match cipher.encrypt(&nonce, data[index].as_ref()) {
            Ok(cipher_text) => {
                let mut data_to_write = Vec::new();

                let path = entry.as_path();
                if let Some(name) = path.file_name() {
                    if name == OsStr::new("config.pass") {
                        data_to_write.extend_from_slice(nonce.as_ref());
                        data_to_write.extend_from_slice(salt.as_ref());
                        data_to_write.extend_from_slice(key_rand.as_ref());
                        data_to_write.extend_from_slice(cipher_text.as_ref());
                    } else {
                        data_to_write.extend_from_slice(nonce.as_ref());
                        data_to_write.extend_from_slice(cipher_text.as_ref());
                    }
                }

                let mut file =  File::create(entry.as_path())?;
                file.write_all(&data_to_write)?;
                file.flush()?;
            }
            Err(_) => return Err(anyhow!("Invalid data!"))
        }
    }
    Ok(())
}

pub(crate) fn change(password: &String, new_password: &String) -> anyhow::Result<()> {
    let decrypted_text = decrypt(&password)?;

    encrypt(&new_password, &decrypted_text)?;
    Ok(())
}
