// 核心改动：不再使用 rand 库和随机 Nonce。

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
// use rand::Rng; // ⚠️ 已移除
use sha2::Digest;

// 定义一个固定的 Nonce (12字节/96位)
// 🚨 警告：这会使加密结果固定，但会带来严重的安全风险！
const FIXED_NONCE_BYTES: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
// ... Args 结构体保持不变
struct Args {
    /// Encrypt mode
    #[clap(long, short)]
    enc: bool,

    /// Decrypt mode
    #[clap(long, short)]
    dec: bool,

    /// Password for encryption/decryption (can be set via CRYPT_PASSWORD env var)
    #[clap(long, short, env = "CRYPT_PASSWORD")]
    password: String,

    /// Input file path (optional). If not provided, reads from stdin.
    input_file: Option<String>,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    // ... 错误检查保持不变

    if args.enc == args.dec {
        eprintln!("Error: You must specify either --enc or --dec, but not both.");
        std::process::exit(1);
    }

    // 确定输入源：文件或标准输入
    let reader: Box<dyn BufRead> = match args.input_file {
        Some(path) => {
            let file = File::open(&path).map_err(|e| {
                io::Error::new(e.kind(), format!("Failed to open file '{}': {}", path, e))
            })?;
            Box::new(BufReader::new(file))
        }
        None => Box::new(BufReader::new(io::stdin())),
    };

    // 派生密钥
    let password_bytes = args.password.as_bytes();
    let key = Key::<Aes256Gcm>::from_slice(&sha256(password_bytes));
    let cipher = Aes256Gcm::new(key);

    // ⚠️ 非安全修改: 在循环外固定 Nonce
    let nonce = Nonce::from_slice(&FIXED_NONCE_BYTES);

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            println!();
            continue;
        }

        if args.enc {
            // 加密模式
            // ⚠️ Nonce 是固定的，因此密文也会固定
            let ciphertext = cipher.encrypt(nonce, line.as_bytes()).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Encryption error: {:?}", e))
            })?;

            // 将 Nonce 和密文一起 Base64 编码 (NONCE 仍然被包含在内，但它是固定的)
            let combined_data = [FIXED_NONCE_BYTES.as_slice(), ciphertext.as_slice()].concat();
            let encoded = general_purpose::STANDARD.encode(&combined_data);
            println!("{}", encoded);
        } else {
            // 解密模式
            let decoded = general_purpose::STANDARD
                .decode(line.as_bytes())
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Base64 decode error: {}", e),
                    )
                })?;

            if decoded.len() < 12 {
                eprintln!("Error: Invalid data format (too short). Skipping line.");
                continue;
            }

            // Nonce 必须从 Base64 数据中提取出来，即使它是固定的
            let nonce_bytes = &decoded[..12];
            let ciphertext = &decoded[12..];
            // ⚠️ 确保提取出的 Nonce 匹配固定的 Nonce，尽管不是必要的，但结构不变
            let line_nonce = Nonce::from_slice(nonce_bytes);

            let plaintext = cipher.decrypt(line_nonce, ciphertext).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Decryption error: {:?}", e),
                )
            })?;

            println!(
                "{}",
                String::from_utf8(plaintext).map_err(|e| io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("UTF-8 decode error: {}", e)
                ))?
            );
        }
    }

    Ok(())
}
