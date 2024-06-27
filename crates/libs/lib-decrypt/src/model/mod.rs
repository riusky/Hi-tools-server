pub use self::error::{Error, Result};
use crate::crypt::error;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use lib_utils::json::is_valid_json;
use lib_utils::time::{now_utc, format_time};
use crate::crypt::{encrypt_aes_plaintext, encrypt_rsa, sign_rsa, decrypt_aes, decrypt_rsa, verify_rsa};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedData {
    a: String, // AES密钥，使用RSA加密
    b: String, // AES IV，使用RSA加密
    c: String, // AES加密的数据
    d: String, // 客户端请求时间，使用RSA加密
    e: String, // 客户端请求ID，使用RSA加密
    f: String, // RSA签名
}

impl EncryptedData {
    /// 加密给定的明文字符串，使用AES和RSA，然后对结果进行签名。
    fn encrypt_and_sign(json_str: &str) -> Result<Self> {
        // 确保输入字符串是有效的JSON
        if !is_valid_json(json_str) {
            return Err(Error::JsonConversionError);
        }

        // 执行AES加密
        let (key, iv, ciphertext) = encrypt_aes_plaintext(json_str)?;

        // 获取当前的UTC时间并格式化
        let now_utc = now_utc();
        let formatted_time = format_time(now_utc);

        // 对密钥、IV和格式化时间执行RSA加密
        let encrypt_rsa_key = encrypt_rsa(&key)?;
        let encrypt_rsa_iv = encrypt_rsa(&iv)?;
        let encrypt_rsa_time = encrypt_rsa(&formatted_time)?;

        // 生成UUID作为客户端请求ID，并使用RSA加密
        let uuid = Uuid::new_v4().to_string();
        let encrypt_rsa_uuid = encrypt_rsa(&uuid)?;

        // 将所有字段收集到一个字符串中以创建签名
        let data_to_sign = format!("{},{},{},{},{}", encrypt_rsa_key, encrypt_rsa_iv, ciphertext, encrypt_rsa_time, encrypt_rsa_uuid);
        let signature = sign_rsa(&data_to_sign)?;

        Ok(Self {
            a: encrypt_rsa_key,
            b: encrypt_rsa_iv,
            c: ciphertext,
            d: encrypt_rsa_time,
            e: encrypt_rsa_uuid,
            f: signature,
        })
    }

    /// 解密EncryptedData，首先验证签名。
    fn verify_and_decrypt(&self) -> Result<String> {
        // 将所有字段收集到一个字符串中以验证签名
        let data_to_verify = format!("{},{},{},{},{}", self.a, self.b, self.c, self.d, self.e);
        
        // 验证签名
        verify_rsa(&data_to_verify, &self.f)?;

        // 解密RSA加密的字段
        let decrypted_key = decrypt_rsa(&self.a)?;
        let decrypted_iv = decrypt_rsa(&self.b)?;

        // 解密AES加密的数据
        let plaintext = decrypt_aes(&decrypted_key, &self.c, &decrypted_iv)?;

        Ok(plaintext)
    }
}

impl FromStr for EncryptedData {
    type Err = Error;

    fn from_str(json_str: &str) -> Result<Self> {
        EncryptedData::encrypt_and_sign(json_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_sign() {
        let json_str = r#"{"key": "value"}"#;
        let encrypted_data = EncryptedData::from_str(json_str).unwrap();

        println!("Encrypted Data: {:?}", encrypted_data);

        // 添加额外的断言来验证加密数据的正确性
    }

    #[test]
    fn test_verify_and_decrypt() {
        let json_str = r#"{"key": "value"}"#;
        let encrypted_data = EncryptedData::from_str(json_str).unwrap();

        let decrypted_data = encrypted_data.verify_and_decrypt().unwrap();
        println!("Decrypted Data: {:?}", decrypted_data);

        assert_eq!(json_str, decrypted_data);
    }
}
