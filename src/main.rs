use aes_gcm::{
    aead::{Aead, KeyInit}, // OsRng 已移除
    Aes256Gcm,
    Key,
    Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use rand::Rng;
use sha2::Digest;
use std::fs::File;
use std::io::{self, BufRead, BufReader}; // Read 已移除 // ⚠️ 修复: 确保 sha2 导入

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Encrypt mode
    #[clap(long, short)]
    enc: bool,

    /// Decrypt mode
    #[clap(long, short)]
    dec: bool,

    /// Password for encryption/decryption (can be set via CRYPT_PASSWORD env var)
    // ⚠️ 修复: clap v4 使用 env = "VAR_NAME" 格式
    #[clap(long, short, env = "CRYPT_PASSWORD")]
    password: String,

    /// Input file path (optional). If not provided, reads from stdin.
    input_file: Option<String>,
}

// 简单的 SHA-256 哈希函数作为密钥派生函数 (KDF)
// ⚠️ 警告：在生产环境中，请改用 Argon2 或 PBKDF2。
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new(); // ⚠️ 修复: 使用 sha2::Sha256
    hasher.update(data);
    hasher.finalize().into()
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.enc == args.dec {
        eprintln!("Error: You must specify either --enc or --dec, but not both.");
        std::process::exit(1);
    }

    // 确定输入源：文件或标准输入
    let reader: Box<dyn BufRead> = match args.input_file {
        Some(path) => {
            // 检查文件是否存在
            let file = File::open(&path).map_err(|e| {
                io::Error::new(e.kind(), format!("Failed to open file '{}': {}", path, e))
            })?;
            Box::new(BufReader::new(file))
        }
        None => Box::new(BufReader::new(io::stdin())),
    };

    // 派生密钥
    let password_bytes = args.password.as_bytes();
    // let key = Key::<Aes256Gcm>::from_slice(&sha256(password_bytes));

    let binding = sha256(password_bytes);
    let key = Key::<Aes256Gcm>::from_slice(&binding);

    let cipher = Aes256Gcm::new(key);

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            // 保留空行
            println!();
            continue;
        }

        if args.enc {
            // 加密模式
            // 生成随机 Nonce (number used once)
            let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
            let nonce = Nonce::from_slice(&nonce_bytes);

            // ⚠️ 修复: 将 aes-gcm::Error 转换为字符串，解决 E0277
            let ciphertext = cipher.encrypt(nonce, line.as_bytes()).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Encryption error: {:?}", e))
            })?;

            // 将 Nonce 和密文一起 Base64 编码
            let combined_data = [nonce_bytes.as_slice(), ciphertext.as_slice()].concat();
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

            let nonce_bytes = &decoded[..12];
            let ciphertext = &decoded[12..];
            let nonce = Nonce::from_slice(nonce_bytes);

            // ⚠️ 修复: 将 aes-gcm::Error 转换为字符串，解决 E0277
            let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
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
