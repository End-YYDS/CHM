use openssl::x509::X509;
use openssl::hash::{hash, MessageDigest};

fn cert_fingerprint_sha256(pem: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let cert = X509::from_pem(pem)?;
    let der = cert.to_der()?;
    let digest = hash(MessageDigest::sha256(), &der)?;
    let hex = digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    Ok(hex)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem = std::fs::read("certs/mini_controller.pem")?;
    let fp = cert_fingerprint_sha256(&pem)?;
    println!("SHA256 Fingerprint= {}", fp);
    Ok(())
}
