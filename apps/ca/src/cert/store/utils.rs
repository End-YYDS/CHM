use openssl::hash::{hash, MessageDigest};

use crate::CaResult;

pub fn hash_sha256(data: &[u8]) -> CaResult<String> {
    let hash = hash(MessageDigest::sha256(), data)?;
    let hex = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    Ok(hex)
}
