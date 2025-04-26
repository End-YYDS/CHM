use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509Builder, X509},
};
use std::fs;
use std::path::Path;
#[allow(unused)]
pub struct Certificate {
    ca_cert: X509,
    ca_key: PKey<Private>,
}
#[allow(unused)]
impl Certificate {
    pub fn load<C: AsRef<Path>, K: AsRef<Path>, S: AsRef<[u8]>>(
        cert_path: C,
        key_path: K,
        passphrase: S,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_pem = fs::read(&cert_path)?;
        let ca_cert = X509::from_pem(&cert_pem)?;
        let key_pem = fs::read(&key_path)?;
        // let ca_key = PKey::private_key_from_pem(&key_pem)?;
        let ca_key = PKey::private_key_from_pem_passphrase(&key_pem, passphrase.as_ref())?;
        Ok(Certificate { ca_cert, ca_key })
    }

    pub fn get_ca_cert(&self) -> &openssl::x509::X509 {
        &self.ca_cert
    }

    pub fn get_ca_key(&self) -> &openssl::pkey::PKey<openssl::pkey::Private> {
        &self.ca_key
    }
    pub fn sign_csr(
        &self,
        csr: &openssl::x509::X509Req,
        days_valid: u32,
    ) -> Result<X509, Box<dyn std::error::Error>> {
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_subject_name(csr.subject_name())?;
        let pubkey = csr.public_key()?;
        builder.set_pubkey(&pubkey)?;
        builder.set_issuer_name(self.ca_cert.subject_name())?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(days_valid)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        builder.sign(&self.ca_key, MessageDigest::sha256())?;
        Ok(builder.build())
    }
}
