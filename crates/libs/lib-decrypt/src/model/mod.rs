
pub use self::error::{Error, Result};
use crate::crypt::error;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use lib_utils::json::is_valid_json;
use crate::crypt::{decrypt_aes, encrypt_aes, encrypt_aes_plaintext};

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedData {
    a: String, // a: aes加密算法的key 被rsa加密
    b: String, // b: aes加密算法的iv 被rsa加密
    c: String, // c: aes加密后的数据
    d: String, // d: 请求发起的客户端时间 被rsa加密
    e: String, // e: 请求发起的客户端ID 被rsa加密
    f: String, // f: rsa签名 rsa私钥签名 公钥验签
}


impl FromStr for EncryptedData {
	type Err = Error;

	fn from_str(json_str: &str) -> Result<Self> {
        // 解析JSON字符串为EncryptedData结构体

        // 判断json_str是否是一个json字符串
        let is_valid_json = is_valid_json(json_str);
        if !is_valid_json {
            return Err(Error::JsonConversionError);
        }

        // 执行aes加密
        let (key,iv,ciphertext) = encrypt_aes_plaintext(json_str)?;

        
		Ok(Self {
            a: "".to_string(),
            b: "".to_string(),
            c: "".to_string(),
            d: "".to_string(),
            e: "".to_string(),
            f: "".to_string(),
		})
	}
}