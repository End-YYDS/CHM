pub mod grpc {
    include!("generated/ca.rs");
}
pub mod mini_controller;

use grpc::{ca_server::Ca, CsrRequest, CsrResponse};
use mini_controller::MiniResult;
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509Builder, X509},
};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tonic::{Request, Response, Status};
pub type CaResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type SignedCert = Vec<u8>;
pub type ChainCerts = Vec<SignedCert>;
pub type PrivateKey = Vec<u8>;
pub type CsrCert = Vec<u8>;
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
    ) -> CaResult<(SignedCert, ChainCerts)> {
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
        for ext in csr.extensions()? {
            builder.append_extension(ext)?;
        }
        builder.sign(&self.ca_key, MessageDigest::sha256())?;
        let leaf = builder.build();
        let cert_der = leaf.to_der()?;
        let chain_der = vec![self.ca_cert.to_der()?];
        Ok((cert_der, chain_der))
    }
    /// 產生 CSR 與對應的私鑰
    ///
    /// # 參數
    /// - `key_bits`: RSA 金鑰長度 (e.g. 2048)
    /// - `country`, `state`, `locality`, `organization`, `common_name`: Subject 欄位
    /// - `subject_alt_names`: 要加入的 SAN DNS 名稱列表
    ///
    /// # 回傳
    /// - `Ok((private_key_pem, csr_pem))`：分別是私鑰和 CSR 的 PEM Bytes
    /// - `Err(e)`：若任何步驟失敗，回傳錯誤
    pub fn generate_csr(
        key_bits: u32,
        country: &str,
        state: &str,
        locality: &str,
        organization: &str,
        common_name: &str,
        subject_alt_names: &[&str],
    ) -> MiniResult<(PrivateKey, CsrCert)> {
        //  產生RSA私鑰
        let rsa = Rsa::generate(key_bits)?;
        let private_key = PKey::from_rsa(rsa)?;
        let mut csr_builder = X509ReqBuilder::new()?;
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", country)?;
        name_builder.append_entry_by_text("ST", state)?;
        name_builder.append_entry_by_text("L", locality)?;
        name_builder.append_entry_by_text("O", organization)?;
        name_builder.append_entry_by_text("CN", common_name)?;
        let name = name_builder.build();
        csr_builder.set_subject_name(&name)?;
        csr_builder.set_pubkey(&private_key)?;
        if !subject_alt_names.is_empty() {
            let mut san_builder = SubjectAlternativeName::new();
            for &name in subject_alt_names {
                // san_builder.dns(dns);
                match name.parse::<IpAddr>() {
                    Ok(_) => san_builder.ip(name),   // IP SAN
                    Err(_) => san_builder.dns(name), // DNS SAN
                };
            }
            let san_ext = san_builder.build(&csr_builder.x509v3_context(None))?;
            let mut extensions = openssl::stack::Stack::new()?;
            extensions.push(san_ext)?;
            csr_builder.add_extensions(&extensions)?;
        }
        csr_builder.sign(&private_key, MessageDigest::sha256())?;
        let csr = csr_builder.build();

        let key_pem = private_key.private_key_to_pem_pkcs8()?;
        let csr_pem = csr.to_pem()?;

        Ok((key_pem, csr_pem))
    }
}

pub struct MyCa {
    pub cert: Arc<Certificate>,
}

#[tonic::async_trait]
impl Ca for MyCa {
    async fn sign_csr(&self, req: Request<CsrRequest>) -> Result<Response<CsrResponse>, Status> {
        let csr_bytes = req.into_inner().csr;
        let csr = X509Req::from_der(&csr_bytes)
            .or_else(|_| X509Req::from_pem(&csr_bytes))
            .map_err(|e| Status::invalid_argument(format!("Invalid CSR: {}", e)))?;
        let (leaf, chain) = self
            .cert
            .sign_csr(&csr, 365)
            .map_err(|e| Status::internal(format!("Sign error: {}", e)))?;
        Ok(Response::new(CsrResponse { cert: leaf, chain }))
    }
}

pub async fn start_grpc(
    addr: SocketAddr,
    cert_handler: Arc<Certificate>,
) -> Result<(), Box<dyn std::error::Error>> {
    let svc = grpc::ca_server::CaServer::new(MyCa { cert: cert_handler });
    println!("gRPC server listening on {}", addr);
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl-C");
        println!("收到CtrlC,開始關閉gRPC...");
    };
    tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_shutdown(addr, shutdown_signal)
        .await?;
    Ok(())
}
