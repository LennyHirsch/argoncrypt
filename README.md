# argoncrypt

File/directory encryption and decryption with Rust, using Argon2 and XChaCha20Poly1305

## Installation

Clone the repo and build that bad boy with `cargo build --release`

Optionally, add the `target/release` directory to your path to call argoncrypt from anywhere. Add `export PATH=$PATH:/path/to/target/release` to your `.bashrc`, save, and reload your terminal.

## Usage

`argoncrypt <path>`

Replace `<path>` with a filepath or directory.
If a filepath is specified, that file will be encrypted. Encrypted files have the suffix `.encrypted` appended to them.

If a directory is specified, `argoncrypt` will encrypt each file inside the specified directory, /including files in subdirectories!/

If no arguments are given, `argoncrypt` will run in the current working directory (i.e., `./`).

To decrypt files/directories, simply run `argoncrypt` again. Any files that have a `.encrypted` suffix will be decrypted.

> [!WARNING]
> `argoncrypt` deletes the unencrypted version of a file after encryption. Make sure you remember the password used for encryption. Use this tool at your own peril, I am not responsible for any data loss.

## Other stuff

`argoncrypt` uses `argon2id` to create a high-entropy key from the password, and XChaCha20Poly1305 to encrypt data.

Thanks to [skerkour](https://github.com/skerkour) for the [inspiration](https://kerkour.com/rust-file-encryption-chacha20poly1305-argon2) behind this script. Go check him out!
