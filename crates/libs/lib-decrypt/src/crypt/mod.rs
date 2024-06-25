//! 此模块提供了加密功能，包括 AES 加密/解密和 RSA 加密/解密。

mod error;
pub use self::error::{Error, Result};
use crate::config::rsa_config;
use base64::engine::{general_purpose, Engine};
use rand::Rng;
use ring::aead;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

/// 生成指定长度的随机字节数组。
///
/// # 参数
///
/// * `len` - 要生成的随机字节数。
///
/// # 返回值
///
/// 包含 `len` 个随机字节的向量。
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen()).collect()
}

/// 使用指定的密钥通过 AES-256-GCM 加密给定的明文。
///
/// # 参数
///
/// * `key` - 加密密钥（对于 AES-256，必须是 32 字节）。
/// * `plaintext` - 要加密的明文。
///
/// # 返回值
///
/// 一个包含 base64 编码的密文和 base64 编码的初始化向量 (IV) 的元组。
///
/// # 错误
///
/// 如果加密过程失败，返回 `Error`。
fn encrypt_aes(key: &[u8], plaintext: &str) -> Result<(String, String)> {
    let iv = generate_random_bytes(12);

    let sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| Error::KeyGenerationError)?;
    let sealing_key = aead::LessSafeKey::new(sealing_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(&iv)
        .map_err(|_| Error::KeyGenerationError)?;

    let mut in_out = plaintext.as_bytes().to_vec();
    in_out.extend_from_slice(&[0u8; 16]);

    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| Error::EncryptionError)?;

    Ok((
        general_purpose::URL_SAFE_NO_PAD.encode(in_out),
        general_purpose::URL_SAFE_NO_PAD.encode(iv),
    ))
}

/// 使用指定的密钥和初始化向量 (IV) 通过 AES-256-GCM 解密给定的密文。
///
/// # 参数
///
/// * `key` - 解密密钥（对于 AES-256，必须是 32 字节）。
/// * `ciphertext` - 要解密的 base64 编码密文。
/// * `iv` - 加密过程中使用的 base64 编码的初始化向量。
///
/// # 返回值
///
/// 解密后的明文字符串。
///
/// # 错误
///
/// 如果解密过程失败，返回 `Error`。
fn decrypt_aes(key: &[u8], ciphertext: &str, iv: &str) -> Result<String> {
    let ciphertext_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(ciphertext)
        .map_err(|_| Error::DecodeError)?;
    let iv_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(iv)
        .map_err(|_| Error::DecodeError)?;

    let opening_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| Error::KeyGenerationError)?;
    let opening_key = aead::LessSafeKey::new(opening_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(&iv_bytes)
        .map_err(|_| Error::KeyGenerationError)?;

    let mut in_out = ciphertext_bytes.to_vec();
    let decrypted_data = opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| Error::DecryptionError)?;

    let decrypted_data_len = decrypted_data.len();
    let plaintext_len = decrypted_data_len - 16;
    let decrypted_plaintext = &decrypted_data[..plaintext_len];

    String::from_utf8(decrypted_plaintext.to_vec()).map_err(|_| Error::Utf8ConversionError)
}

/// 使用公钥通过 RSA 加密给定的明文。
///
/// # 参数
///
/// * `plaintext` - 要加密的明文。
///
/// # 返回值
///
/// base64 编码的密文。
///
/// # 错误
///
/// 如果加密过程失败，返回 `Error`。
fn encrypt_rsa(plaintext: &str) -> Result<String> {
    let public_key_pem = String::from_utf8(rsa_config().PUBLIC_KEY.to_vec())
        .map_err(|_| Error::Utf8ConversionError)?;
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem)
        .map_err(|_| Error::RsaKeyGenerationError)?;

    let encrypted_data = public_key
        .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, plaintext.as_bytes())
        .map_err(|_| Error::RsaEncryptionError)?;

    Ok(general_purpose::URL_SAFE_NO_PAD.encode(encrypted_data))
}

/// 使用私钥通过 RSA 解密给定的密文。
///
/// # 参数
///
/// * `enc_data` - 要解密的 base64 编码密文。
///
/// # 返回值
///
/// 解密后的明文字符串。
///
/// # 错误
///
/// 如果解密过程失败，返回 `Error`。
fn decrypt_rsa(enc_data: &str) -> Result<String> {
    let enc_data = general_purpose::URL_SAFE_NO_PAD
        .decode(enc_data)
        .map_err(|_| Error::DecodeError)?;

    let private_key_pem = String::from_utf8(rsa_config().PRIVATE_KEY.to_vec())
        .map_err(|_| Error::Utf8ConversionError)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|_| Error::RsaKeyGenerationError)?;

    let decrypted_data = private_key
        .decrypt(Pkcs1v15Encrypt, &enc_data)
        .map_err(|_| Error::RsaDecryptionError)?;

    String::from_utf8(decrypted_data).map_err(|_| Error::Utf8ConversionError)
}

/// 加密函数的单元测试。
#[cfg(test)]
mod tests {
    use super::*;
    pub type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

    /// 测试 AES 和 RSA 加密/解密函数。
    #[tokio::test]
    async fn test_decrypt_ok() -> Result<()> {
        let key = generate_random_bytes(32);
        println!(
            "生成的密钥: {}",
            general_purpose::URL_SAFE_NO_PAD.encode(&key)
        );

        let plaintext = "Hello, AES with random IV and Key!";
        let (encrypted, iv) = encrypt_aes(&key, plaintext)?;
        println!("IV: {}", iv);
        println!("加密后的密文: {}", encrypted);

        let decrypted = decrypt_aes(&key, &encrypted, &iv)?;
        println!("解密后的明文: {}", decrypted);
        assert_eq!(plaintext, decrypted);

        let rsa_str = encrypt_rsa("123")?;
        println!("加密后的 RSA 字符串: {}", rsa_str);

        let rsa_str_en = decrypt_rsa(&rsa_str)?;
        println!("解密后的 RSA 字符串: {}", rsa_str_en);
        assert_eq!("123", rsa_str_en);

        Ok(())
    }
}
