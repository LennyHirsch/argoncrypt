use anyhow::{anyhow, Ok};
use chacha20poly1305::{
    aead::{stream, NewAead},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    env,
    fs::{metadata, remove_file, File},
    io::{stdin, Read, Write},
};
use walkdir::WalkDir;
use zeroize::Zeroize;

struct Opts {
    recursive: bool,
    delete_old: bool,
    help: bool,
    file: String,
}

fn main() -> Result<(), anyhow::Error> {
    let mut opts = Opts {
        recursive: false,
        delete_old: false,
        help: false,
        file: "./".to_string(),
    };

    let args: Vec<String> = env::args().collect();
    args.iter().for_each(|arg| match arg.as_str() {
        "argoncrypt" => {}
        "-r" => opts.recursive = true,
        "-d" => opts.delete_old = true,
        "-h" => opts.help = true,
        _ => opts.file = arg.to_string(),
    });

    let md = metadata(opts.file.clone()).unwrap();
    if md.is_dir() {
        let mut password = String::new();
        let mut user_confirm = String::new();

        if opts.recursive {
            println!("You are about to work recursively on a directory.\nThis will affect all files within {}, as well as files in subdirectories. Continue? (y/N)", opts.file);
            let _ = stdin().read_line(&mut user_confirm).unwrap();
            if user_confirm.to_lowercase() == "y\n" {
                password = get_password()?;
                let walker = WalkDir::new(&opts.file).into_iter().filter_map(|e| e.ok());
                for entry in walker {
                    let md = entry.path().metadata().unwrap();
                    if md.is_file() {
                        let _ = run_encrypt_decrypt(
                            entry.path().to_str().unwrap(),
                            &password,
                            opts.delete_old,
                        );
                    }
                }
            }
        } else {
            println!("You are about to work on a directory.\nThis will affect all files within {}. Continue? (y/N)", opts.file);
            let _ = stdin().read_line(&mut user_confirm).unwrap();
            if user_confirm.to_lowercase() == "y\n" {
                password = get_password()?;
                let walker = WalkDir::new(&opts.file)
                    .max_depth(1)
                    .into_iter()
                    .filter_map(|e| e.ok());
                for entry in walker {
                    let md = entry.path().metadata().unwrap();
                    if md.is_file() {
                        let _ = run_encrypt_decrypt(
                            entry.path().to_str().unwrap(),
                            &password,
                            opts.delete_old,
                        );
                    }
                }
            }
        }
        password.zeroize();
    } else {
        let mut password = get_password()?;
        let _ = run_encrypt_decrypt(&opts.file, &password, opts.delete_old);
        password.zeroize();
    }

    Ok(())
}

fn get_password() -> Result<String, anyhow::Error> {
    let password = rpassword::prompt_password("Password: ")?;
    let mut confirm = rpassword::prompt_password("Confirm: ")?;

    if password != confirm {
        panic!("Password did not match");
    }

    confirm.zeroize();
    Ok(password)
}

fn run_encrypt_decrypt(
    source_file_path: &str,
    password: &str,
    delete_old: bool,
) -> Result<(), anyhow::Error> {
    if source_file_path.ends_with(".encrypted") {
        let dist = source_file_path
            .strip_suffix(".encrypted")
            .unwrap()
            .to_string();
        decrypt_file(&source_file_path, &dist, &password, delete_old)?;
    } else {
        let dist = source_file_path.to_owned() + ".encrypted";
        encrypt_file(&source_file_path, &dist, &password, delete_old)?;
    }

    Ok(())
}

fn encrypt_file(
    source_file_path: &str,
    dist_file_path: &str,
    password: &str,
    delete_old: bool,
) -> Result<(), anyhow::Error> {
    let argon2_config = argon2_config();
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut source_file = File::open(source_file_path)?;
    let mut dist_file = File::create(dist_file_path)?;

    dist_file.write(&salt)?;
    dist_file.write(&nonce)?;

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
            println!("Encrypted {}", source_file_path);
            if delete_old {
                remove_file(source_file_path)?;
            }
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

fn decrypt_file(
    encrypted_file_path: &str,
    dist: &str,
    password: &str,
    delete_old: bool,
) -> Result<(), anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut dist_file = File::create(dist)?;

    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
            println!("Decrypted {}", encrypted_file_path);
            if delete_old {
                remove_file(encrypted_file_path)?;
            }
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

fn argon2_config<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}
