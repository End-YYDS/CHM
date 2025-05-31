
use openssl::hash::{hash, MessageDigest};
use openssl::x509::X509;

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

fn cert_serial_sha256(cert: X509) -> Result<String, Box<dyn std::error::Error>> {
    let serial = cert.serial_number();
    let digest = hash(MessageDigest::sha256(), serial.to_bn()?.to_vec().as_slice())?;
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
    let fp1 = cert_serial_sha256(X509::from_pem(&pem)?)?;
    println!("SHA256 Fingerprint= {}", fp);
    println!("SHA256 Serial= {}", fp1);
    Ok(())
}
