mod config;
pub mod crypt;
pub mod model;


// main.rs

use rsa::{pkcs8::{DecodePrivateKey, DecodePublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use base64::{encode, decode};


fn main() {



    let public_key = "-----BEGIN PUBLIC KEY-----";

    let private_key = "-----BEGIN PRIVATE KEY-----";

    let public_key = RsaPublicKey::from_public_key_pem(public_key).expect("failed to generate a key");
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key).expect("failed to generate a key");

    // 待加密的数据
    let data = b"hello, world!";

    // 加密数据
    let enc_data = encrypt_rsa(&public_key, data).expect("encryption failed");

        // 将加密数据编码为 Base64
        let enc_data_b64 = encode(&enc_data);
        println!("Encrypted data (Base64): {}", enc_data_b64);
    

    // 解密数据
    let dec_data = decrypt_rsa(&private_key, &enc_data).expect("decryption failed");

    // 输出解密后的数据
    println!("Decrypted data: {}", String::from_utf8(dec_data).expect("failed to convert to string"));
}

// RSA 加密函数
fn encrypt_rsa(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let encrypted_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)?;
    Ok(encrypted_data)
}

// RSA 解密函数
fn decrypt_rsa(private_key: &RsaPrivateKey, enc_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, enc_data)?;
    Ok(decrypted_data)
}
