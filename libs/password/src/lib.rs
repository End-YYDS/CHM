use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
pub fn encode_base64(input: &str) -> String {
    general_purpose::STANDARD.encode(input.as_bytes())
}
pub fn decode_base64(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    let decoded_bytes = general_purpose::STANDARD.decode(input)?;
    let decoded_string = String::from_utf8(decoded_bytes)?;
    Ok(decoded_string)
}
pub fn hash_password(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
    let encoded_hash = general_purpose::STANDARD.encode(password_hash.as_bytes());
    Ok(encoded_hash)
}

pub fn verify_password(
    password: &str,
    encoded_hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let decoded_hash = general_purpose::STANDARD.decode(encoded_hash)?;
    let decoded_hash_str = String::from_utf8(decoded_hash)?;

    let parsed_hash = PasswordHash::new(&decoded_hash_str)?;
    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
use rand::{distr::Alphanumeric, Rng};
pub fn generate_otp(len: usize) -> String {
    let rng = rand::rng();
    rng.sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_base64_roundtrip() {
        let password = "test_password";
        let encoded_hash = hash_password(password).unwrap();
        assert!(!encoded_hash.is_empty());
        let is_valid = verify_password(password, &encoded_hash).unwrap();
        assert!(is_valid);
        let is_invalid = verify_password("wrong_password", &encoded_hash).unwrap();
        assert!(!is_invalid);
    }
    #[test]
    fn generate_otp_test() {
        let otp = generate_otp(6);
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
