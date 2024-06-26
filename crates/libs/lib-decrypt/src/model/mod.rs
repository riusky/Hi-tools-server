
pub use self::error::{Error, Result};
use crate::crypt::error;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use lib_utils::json::is_valid_json;
use lib_utils::time::now_utc;
use lib_utils::time::format_time;
use crate::crypt::{decrypt_aes, encrypt_aes, encrypt_aes_plaintext,encrypt_rsa};

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
        let now_utc = now_utc();
        let format_time = format_time(now_utc);
        
        // 执行rsa加密
        let encrypt_rsa_key = encrypt_rsa(&key)?;
        let encrypt_rsa_iv = encrypt_rsa(&iv)?;
        let encrypt_rsa_time = encrypt_rsa(&format_time)?;
        
        // 执行rsa签名




        
		Ok(Self {
            a: encrypt_rsa_key,
            b: encrypt_rsa_iv,
            c: ciphertext,
            d: encrypt_rsa_time,
            e: "".to_string(),
            f: "".to_string(),
		})
	}
}