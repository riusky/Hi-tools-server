mod error;
use ring::aead;
use rand::Rng;
use hex::{encode, decode};
pub use self::error::{Error, Result};

const TAG_LEN: usize = 16; // AES-GCM 的 Tag 长度固定为 16 字节

fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen()).collect()
}

fn encrypt_aes(key: &[u8], plaintext: &str) -> Result<(String, String)> {

    // 生成随机初始化向量 (IV)
    let iv = generate_random_bytes(12); // GCM 推荐使用 12 字节的 IV

    // 创建密封器
    let sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::Unspecified)?;
    let sealing_key = aead::LessSafeKey::new(sealing_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(&iv).map_err(|_| Error::Unspecified)?;

    // 将明文转换为字节数组
    let mut in_out = plaintext.as_bytes().to_vec();
    in_out.extend_from_slice(&[0u8; TAG_LEN]);

    // 执行加密
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out).map_err(|_| Error::FailDecrypt)?;

    // 返回加密后的数据和 IV
    Ok((encode(in_out), encode(iv)))
}

fn decrypt_aes(key: &[u8], ciphertext: &str, iv: &str) -> Result<String> {
    // 将密文和 IV 转换为字节数组
    let ciphertext_bytes = decode(ciphertext).map_err(|_| Error::FailDecode)?;
    let iv_bytes = decode(iv).map_err(|_| Error::FailDecode)?;

    // 创建解封器
    let opening_key = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::Unspecified)?;
    let opening_key = aead::LessSafeKey::new(opening_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(&iv_bytes).map_err(|_| Error::Unspecified)?;

    // 执行解密
    let mut in_out = ciphertext_bytes.to_vec();
    let decrypted_data = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out).map_err(|_| Error::FailDecrypt)?;

    let decrypt_str = String::from_utf8(decrypted_data.to_vec()).map_err(|_| Error::FailDecode)?;
    // 返回解密后的数据
    Ok(decrypt_str)
}




// region:    --- Tests
#[cfg(test)]
mod tests {
	pub type Result<T> = core::result::Result<T, Error>;
	pub type Error = Box<dyn std::error::Error>; // For tests.

	use super::*;

	#[tokio::test]
	async fn test_decrypt_ok() -> Result<()> {


    // 生成随机密钥
        let key = generate_random_bytes(32); // AES-256 使用 32 字节的密钥
        println!("Generated Key: {}", encode(&key));

        let plaintext = "Hello, AES with random IV and Key!";

        let (encrypted, iv) = encrypt_aes(&key, plaintext).unwrap();
        println!("IV: {}", iv);
        println!("Encrypted: {}", encrypted);

        let decrypted = decrypt_aes(&key, &encrypted, &iv).unwrap();
        println!("Decrypted: {}", decrypted);
		Ok(())
	}
}
// endregion: --- Tests