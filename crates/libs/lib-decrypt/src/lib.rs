mod crypt;
mod model;


// main.rs

use rsa::{pkcs8::{DecodePrivateKey, DecodePublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use base64::{encode, decode};


fn main() {



    let public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArZpJtefGfboTHLzW70E5
auu11XW1TValiIUrLzGhNt/J/FrcXLp/1fALOvMRSVF2Tddzxtd+TMhPrRRA6LoV
9nWWXkuvtQ+oSoGzFGEcyBVl+vvPpSB9xavRgmbsVKuNWBw0t3Xwe78CE200oYMI
43gq8/Abfbq/eiEn3vrKbmlvqrLQN0PWNq+93WUW1e2gohSiACr7uPWjbfRZF5o1
rz0hML8gp8yruO+zJOrvbqbOsKzj90BFHe03BeZfI+el8ID0gRSWvi4Nbf24igYK
4NXJS7/8hZZ7xCb9/uZajB/NM1HHRS1GRIdQQ7Cr0iCV/hKO6p04hKU+apDCL5Br
twIDAQAB
-----END PUBLIC KEY-----";

let private_key = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCtmkm158Z9uhMc
vNbvQTlq67XVdbVNVqWIhSsvMaE238n8Wtxcun/V8As68xFJUXZN13PG135MyE+t
FEDouhX2dZZeS6+1D6hKgbMUYRzIFWX6+8+lIH3Fq9GCZuxUq41YHDS3dfB7vwIT
bTShgwjjeCrz8Bt9ur96ISfe+spuaW+qstA3Q9Y2r73dZRbV7aCiFKIAKvu49aNt
9FkXmjWvPSEwvyCnzKu477Mk6u9ups6wrOP3QEUd7TcF5l8j56XwgPSBFJa+Lg1t
/biKBgrg1clLv/yFlnvEJv3+5lqMH80zUcdFLUZEh1BDsKvSIJX+Eo7qnTiEpT5q
kMIvkGu3AgMBAAECggEBAJRrWiV4+Iw472ocUK3QV6R/zL+omM58C53CLH92sNvX
TDrB+7ATioN/bDqD4P2L9dbrIoKXbdV7VBMnQ680mN5S/bG0h44GytyYMmBz/kVZ
dgy0CHymYKEFGmOgVuC0omz4AGHxJR7G2KF/NgX3nzvKWv6fAwHlDRr/CbVrOHJX
rYkalq+mfJeEy1Xs1svjKCwhQmCR2edw5L84ZscSh5El1oHQvHH8gRph+uD7/uYl
X5kosYgYMYtFxhpgRDYIw+44Vgz9uwi52S3ejlmWSZc2NPKP/4G/5JRW19NtfP6+
z3Lex8Dvw3Kfa7ayrAGi4o2kK5Cxa+S1NEdN0nyvJ3ECgYEA2YLziMIlZYKKTmhD
ZKgvvZ/CQ5mV3MZTET6LJHzFgWKOSweiCQ8ifSuzQycnQeS8rTxTjuxqVYYQM8xw
iKLhkUMsPhXkslSiMAqPKIPPW8NNwkJMppx5svipwdoK6aEk6rMGiLfX358np0UC
NpFhzyPsg3b7vyPZxrqI4q3DWLsCgYEAzFJPrZwT6914jOWSzWpmVe5r/5hbHr2o
nEE02qcynLmei49TQG47nd3F6+XKn46Xiv7aCYggpkgjQktCZcuFZnBl06UdFhDe
Fq9JjYdpjw/J7gN/VVq1jSHPHD37B3JLvI/Remgy+fwWxjMA8XRl5mvgpUIGgDHG
ZDZZZM8u1zUCgYEAnR7gJuD/vJUQrVTZoeNwIQ0/ei9+tu04YhOI1YGf9jeoTACm
ht687ihcJN0qmYnO1WDnhy22HjNqjtBWVg063gDk+7A69Kr4QbXO9dhJOKMbD4Fu
90e/DY5cqiCEk4GJNlS+GpKayPmh3k2WLK7WNZhgqBKSBd+y18A1U3Fr1DMCgYAz
jOTrgYCJNvSOX/G9AAZX0fLPpwn+ZI2g9ta2AA9F+ZMl1QCFNgq2ltiz3uNThG95
szkhxIWwTm0O8dwLwOCkauFWF8eR5KmUAZ/GJI8eeDZTZfB/gYZi2E/f6Udnpo+z
QHnyr02FQvQgB4hKYzq+eyNPrqvjNiu+5vOA+sDvrQKBgENZfMdTaKkdc8vkJTwB
znfl/YF7weaDbSEWL2ZPHroglV2NVRbpMj9Dr8/o5AHw5I5PsJHaiO5HrPXpid4x
yjjJighUh6t2pd9up//BLSBBFwc7aZmtNU0EO3tb+nVK2p7zg7Ub5AFy6DCcRlq7
sKW25PgeYGTljuFD5lUJ8kl4
-----END PRIVATE KEY-----";

    let public_key = RsaPublicKey::from_public_key_pem(public_key).expect("failed to generate a key");
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key).expect("failed to generate a key");

    // 待加密的数据
    let data = b"hello, world!";

    // 加密数据
    let enc_data = encrypt(&public_key, data).expect("encryption failed");

        // 将加密数据编码为 Base64
        let enc_data_b64 = encode(&enc_data);
        println!("Encrypted data (Base64): {}", enc_data_b64);
    

    // 解密数据
    let dec_data = decrypt(&private_key, &enc_data).expect("decryption failed");

    // 输出解密后的数据
    println!("Decrypted data: {}", String::from_utf8(dec_data).expect("failed to convert to string"));
}

// RSA 加密函数
fn encrypt(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let encrypted_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)?;
    Ok(encrypted_data)
}

// RSA 解密函数
fn decrypt(private_key: &RsaPrivateKey, enc_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, enc_data)?;
    Ok(decrypted_data)
}
