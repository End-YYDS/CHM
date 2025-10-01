// use argon2::{
//     password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher,
// PasswordVerifier, SaltString},     Argon2,
// };
// use base64::{engine::general_purpose, Engine as _};
//
// pub fn generate_64_keys() -> String {
//     let mut key_bytes = [0u8; 64];
//     rand::rng().fill_bytes(&mut key_bytes);
//     encode_base64(key_bytes)
// }
// pub fn decode_key64_from_base64(s: &str) -> anyhow::Result<[u8; 64]> {
//     let bytes =
//         general_purpose::STANDARD.decode(s).map_err(|e|
// anyhow::anyhow!("invalid base64: {e}"))?;
//
//     if bytes.len() != 64 {
//         return Err(anyhow::anyhow!("session key must be exactly 64 bytes, got
// {}", bytes.len()));     }
//     let mut fixed = [0u8; 64];
//     fixed.copy_from_slice(&bytes);
//     Ok(fixed)
// }
// pub fn encode_base64(input: impl AsRef<[u8]>) -> String {
//     general_purpose::STANDARD.encode(input)
// }
// pub fn decode_base64<T>(input: &str) -> anyhow::Result<T>
// where
//     T: TryFrom<Vec<u8>, Error = anyhow::Error>,
// {
//     let decoded_bytes = general_purpose::STANDARD
//         .decode(input)
//         .map_err(|e| anyhow::anyhow!("invalid base64: {e}"))?;
//     T::try_from(decoded_bytes)
// }
// #[derive(Clone, Copy, Debug, PartialEq, Eq)]
// pub struct Key64([u8; 64]);
//
// impl Key64 {
//     pub fn into_inner(self) -> [u8; 64] {
//         self.0
//     }
//     pub fn as_array(&self) -> &[u8; 64] {
//         &self.0
//     }
// }
// impl TryFrom<Vec<u8>> for Key64 {
//     type Error = anyhow::Error;
//
//     fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
//         if value.len() != 64 {
//             anyhow::bail!("expected 64 bytes, got {}", value.len());
//         }
//         let mut arr = [0u8; 64];
//         arr.copy_from_slice(&value);
//         Ok(Key64(arr))
//     }
// }
// pub fn hash_password(password: &str) -> Result<String, Box<dyn
// std::error::Error>> {     let salt = SaltString::generate(&mut OsRng);
//     let argon2 = Argon2::default();
//     let password_hash = argon2.hash_password(password.as_bytes(),
// &salt)?.to_string();     let encoded_hash =
// general_purpose::STANDARD.encode(password_hash.as_bytes());
//     Ok(encoded_hash)
// }
//
// pub fn verify_password(
//     password: &str,
//     encoded_hash: &str,
// ) -> Result<bool, Box<dyn std::error::Error>> {
//     let decoded_hash = general_purpose::STANDARD.decode(encoded_hash)?;
//     let decoded_hash_str = String::from_utf8(decoded_hash)?;
//
//     let parsed_hash = PasswordHash::new(&decoded_hash_str)?;
//     let argon2 = Argon2::default();
//
//     match argon2.verify_password(password.as_bytes(), &parsed_hash) {
//         Ok(_) => Ok(true),
//         Err(_) => Ok(false),
//     }
// }
// use rand::{distr::Alphanumeric, Rng, RngCore};
// pub fn generate_otp(len: usize) -> String {
//     let rng = rand::rng();
//     rng.sample_iter(&Alphanumeric).take(len).map(char::from).collect()
// }
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn password_base64_roundtrip() {
//         let password = "test_password";
//         let encoded_hash = hash_password(password).unwrap();
//         assert!(!encoded_hash.is_empty());
//         let is_valid = verify_password(password, &encoded_hash).unwrap();
//         assert!(is_valid);
//         let is_invalid = verify_password("wrong_password",
// &encoded_hash).unwrap();         assert!(!is_invalid);
//     }
//     #[test]
//     fn generate_otp_test() {
//         let otp = generate_otp(6);
//         assert_eq!(otp.len(), 6);
//         assert!(otp.chars().all(|c| c.is_ascii_alphanumeric()));
//     }
// }

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::{distr::Alphanumeric, rngs::OsRng, Rng, TryRngCore};

use argon2::{
    password_hash::{
        rand_core::OsRng as argon_osrng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};

/// =============================
/// Key（64 bytes）
/// =============================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key64([u8; 64]);

impl Key64 {
    /// 產生一把新的 64 bytes 金鑰（使用 OsRng）
    pub fn generate() -> Self {
        let mut buf = [0u8; 64];
        OsRng.try_fill_bytes(&mut buf).unwrap();
        Self(buf)
    }

    /// 從 base64 字串載入
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes =
            general_purpose::STANDARD.decode(s).map_err(|e| anyhow!("invalid base64: {e}"))?;
        if bytes.len() != 64 {
            bail!("session key must be exactly 64 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// 轉成 base64 字串（STANDARD）
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.0)
    }

    pub fn as_array(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; 64] {
        self.0
    }
}

/// 產生一把隨機 key，直接回傳 base64 字串（方便存 config）
pub fn generate_key64_base64() -> String {
    Key64::generate().to_base64()
}

/// 與上面 `Key64::from_base64` 等價：回傳裸陣列
pub fn decode_key64_from_base64(s: &str) -> Result<[u8; 64]> {
    Ok(Key64::from_base64(s)?.into_inner())
}

/// 編碼
pub fn encode_base64(input: impl AsRef<[u8]>) -> String {
    general_purpose::STANDARD.encode(input)
}

/// 泛型解碼：任何 `TryFrom<Vec<u8>>` 的型別都能接（例如 Vec<u8>, String,
/// Key64…）
pub fn decode_base64_as<T>(input: &str) -> Result<T>
where
    T: TryFrom<Vec<u8>>,
    <T as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
{
    let decoded =
        general_purpose::STANDARD.decode(input).map_err(|e| anyhow!("invalid base64: {e}"))?;
    T::try_from(decoded).map_err(|e| anyhow!(e.to_string()))
}

/// 常用速寫
pub fn decode_base64_vec(input: &str) -> Result<Vec<u8>> {
    decode_base64_as::<Vec<u8>>(input)
}

pub fn decode_base64_string(input: &str) -> Result<String> {
    let bytes = decode_base64_vec(input)?;
    Ok(String::from_utf8(bytes)?)
}

/// 密碼雜湊（Argon2id）
pub fn hash_password_phc(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut argon_osrng);
    let argon2 = Argon2::default(); // Argon2id，預設參數足夠通用
    let phc = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
    Ok(phc)
}

pub fn verify_password_phc(password: &str, phc: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc)?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}

/// 相容版：把 PHC 字串再用 base64 包一層
pub fn hash_password_b64(password: &str) -> Result<String> {
    let phc = hash_password_phc(password)?;
    Ok(encode_base64(phc.as_bytes()))
}

pub fn verify_password_b64(password: &str, encoded_phc_b64: &str) -> Result<bool> {
    let phc = decode_base64_string(encoded_phc_b64)?;
    verify_password_phc(password, &phc)
}

/// OTP 產生
pub fn generate_otp(len: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key64_roundtrip_base64() {
        let b64 = generate_key64_base64();
        let arr = decode_key64_from_base64(&b64).unwrap();
        assert_eq!(b64, Key64(arr).to_base64());
    }

    #[test]
    fn base64_generic_decode() {
        let s = "hello";
        let enc = encode_base64(s.as_bytes());

        let v: Vec<u8> = decode_base64_as(&enc).unwrap();
        assert_eq!(v, b"hello");

        let ss: String = String::from_utf8(v.clone()).unwrap();
        assert_eq!(ss, "hello");

        // 轉成 Key64 會失敗（長度不符），這裡只是示範泛型錯誤
        assert!(Key64::from_base64(&enc).is_err());
    }

    #[test]
    fn password_phc_roundtrip() {
        let pwd = "test_password";
        let phc = hash_password_phc(pwd).unwrap();
        assert!(verify_password_phc(pwd, &phc).unwrap());
        assert!(!verify_password_phc("wrong", &phc).unwrap());
    }

    #[test]
    fn password_b64_roundtrip() {
        let pwd = "test_password";
        let b64 = hash_password_b64(pwd).unwrap();
        assert!(verify_password_b64(pwd, &b64).unwrap());
        assert!(!verify_password_b64("wrong", &b64).unwrap());
    }
}
