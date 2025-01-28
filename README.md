# argoncrypt

File/directory encryption and decryption with Rust, using Argon2 and XChaCha20Poly1305

## Installation

Clone the repo and build that bad boy with `cargo build --release`

Optionally, add the `target/release` directory to your path to call `argoncrypt` from anywhere. Add `export PATH=$PATH:/path/to/target/release` to your `.bashrc`, save, and reload your terminal.

## Usage

`argoncrypt <path>`

Replace `<path>` with a filepath or directory.

- If a filepath is specified, that file will be encrypted. Encrypted files have the suffix `.encrypted` appended to them.

- If a directory is specified, `argoncrypt` will encrypt each file inside the specified directory, *including any files in subdirectories!*

- If no arguments are given, `argoncrypt` will run in the current working directory (i.e., `./`). Again, *any files in subdirectories will also be encrypted!*

To decrypt files/directories, simply run `argoncrypt` again. Any files that have a `.encrypted` suffix will be decrypted.

## Optional flags

- `-r`: recursive. With this flag enabled, `argoncrypt` will work through the specified directory as well as any subdirectories.

- `-d`: delete old. With this flag enabled, old files will be deleted. If you are encrypting, the unencrypted files will be deleted. If you are decrypting, the encrypted files will be deleted. USE WITH CARE!!!

> [!WARNING]
> Make sure you remember the password used for encryption. If the `-d` flag is enabled, original files will be deleted!
>
> Use this tool at your own peril, I am not responsible for any data loss! This code has not been audited, and I am by no means an expert in cryptography.

## Other stuff

`argoncrypt` uses `argon2id` to create a high-entropy key from your password, and `XChaCha20Poly1305` to encrypt data.

Thanks to [skerkour](https://github.com/skerkour) for the [inspiration](https://kerkour.com/rust-file-encryption-chacha20poly1305-argon2) behind this script. Go check him out!
