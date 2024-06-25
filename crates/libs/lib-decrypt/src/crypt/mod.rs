mod error;
use ring::aead;
use rand::Rng;
pub use self::error::{Error, Result};
use rsa::{pkcs8::{DecodePrivateKey, DecodePublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use base64::prelude::*;
use crate::config::rsa_config;

// const TAG_LEN: usize = 16; // AES-GCM 的 Tag 长度固定为 16 字节

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
    in_out.extend_from_slice(&[0u8; 16]);

    // 执行加密
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out).map_err(|_| Error::FailDecrypt)?;

    // 返回加密后的数据和 IV
    Ok((BASE64_STANDARD.encode(in_out), BASE64_STANDARD.encode(iv)))
}

fn decrypt_aes(key: &[u8], ciphertext: &str, iv: &str) -> Result<String> {
    // 将密文和 IV 转换为字节数组
    let ciphertext_bytes = BASE64_STANDARD.decode(ciphertext).map_err(|_| Error::FailDecode)?;
    let iv_bytes = BASE64_STANDARD.decode(iv).map_err(|_| Error::FailDecode)?;

    // 创建解封器
    let opening_key = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::Unspecified)?;
    let opening_key = aead::LessSafeKey::new(opening_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(&iv_bytes).map_err(|_| Error::Unspecified)?;

    // 执行解密
    let mut in_out = ciphertext_bytes.to_vec();
    let decrypted_data = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out).map_err(|_| Error::FailDecrypt)?;

    let decrypt_str = String::from_utf8(decrypted_data.to_vec()).map_err(|_| Error::FailDecode)?;
    // 返回解密后的数据
    Ok(BASE64_STANDARD.encode(decrypt_str))
}



// RSA 加密函数
fn encrypt_rsa(plaintext: &str) -> Result<String> {

    let public_key_der = &rsa_config().PUBLIC_KEY;
    println!("{}",String::from_utf8(public_key_der.to_vec()).unwrap());

    let public_key = RsaPublicKey::from_public_key_der(public_key_der).expect("failed to generate a key");
    let data = plaintext.as_bytes();
    let mut rng = rand::thread_rng();
    let encrypted_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data).map_err(|_| Error::FailDecode)?;
    let decrypt_str = String::from_utf8(encrypted_data).map_err(|_| Error::FailDecode)?;
    Ok(BASE64_STANDARD.encode(decrypt_str))
}

// RSA 解密函数
fn decrypt_rsa(enc_data: &[u8]) -> Result<String> {
    let private_key_der = &rsa_config().PRIVATE_KEY;
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der).expect("failed to generate a key");
    let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, enc_data).map_err(|_| Error::FailDecode)?;
    let decrypt_str = String::from_utf8(decrypted_data).map_err(|_| Error::FailDecode)?;
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
        println!("Generated Key: {}", BASE64_STANDARD.encode(&key));

        let plaintext = "Hello, AES with random IV and Key!";

        let (encrypted, iv) = encrypt_aes(&key, plaintext).unwrap();
        println!("IV: {}", iv);
        println!("Encrypted: {}", encrypted);

        let decrypted = decrypt_aes(&key, &encrypted, &iv).unwrap();
        let decode = BASE64_STANDARD.decode(decrypted).unwrap();
        println!("Decrypted: {}",  String::from_utf8(decode).unwrap());


        let rsa_str = encrypt_rsa("123").unwrap();
        println!("rsa_str: {}",rsa_str);

		Ok(())
	}
}
// endregion: --- Tests