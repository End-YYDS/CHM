// pub mod grpc {
//     include!("generated/ca.rs");
// }
pub mod config;
mod connection;
pub mod crl;
pub mod mini_controller;
use grpc::{ca::*, tonic, tonic_health};
use mini_controller::MiniResult;
use openssl::{
    hash::{hash, MessageDigest},
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::SubjectAlternativeName, X509Builder, X509NameBuilder, X509Req, X509ReqBuilder,
        X509,
    },
};
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tonic::{
    transport::{Identity, ServerTlsConfig},
    Request, Status,
};
use tonic_health::server::health_reporter;

use crate::{connection::MyCa, crl::SimpleCrl};
/// 定義一個簡化的結果類型，用於返回結果或錯誤
pub type CaResult<T> = Result<T, Box<dyn std::error::Error>>;
/// 定義已經簽署的憑證類型
pub type SignedCert = Vec<u8>;
/// 定義憑證鏈類型，包含已簽署的憑證和 CA 憑證
pub type ChainCerts = Vec<SignedCert>;
/// 定義私鑰類型
pub type PrivateKey = Vec<u8>;
/// 定義 CSR 憑證類型
pub type CsrCert = Vec<u8>;

#[allow(unused)]
/// 憑證處理器，負責載入 CA 憑證和金鑰，簽署 CSR，並提供 CRL 驗證功能
pub struct Certificate {
    /// CA 憑證
    ca_cert: X509,
    /// CA 私鑰
    ca_key: PKey<Private>,
    /// CRL 驗證器
    crl: Arc<crl::CrlVerifier>,
}
#[allow(unused)]
impl Certificate {
    /// 從指定的憑證和金鑰檔案載入 CA 憑證和金鑰
    /// # 參數
    /// * `cert_path`: CA 憑證檔案路徑
    /// * `key_path`: CA 金鑰檔案路徑
    /// * `passphrase`: 金鑰的密碼短語
    /// # 回傳
    /// * `Ok(Certificate)`：載入成功，返回憑證和金鑰
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
    pub fn load<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        passphrase: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_pem = fs::read(&cert_path)?;
        let key_pem = fs::read(&key_path)?;
        let ca_cert = X509::from_pem(&cert_pem)
            .or_else(|_| X509::from_der(&cert_pem))
            .map_err(|e| format!("無法解析CA憑證: {}", e))?;
        let ca_key = if passphrase.is_empty() {
            PKey::private_key_from_pem(&key_pem)
        } else {
            PKey::private_key_from_pem_passphrase(&key_pem, passphrase.as_bytes())
        }
        .map_err(|e| format!("無法解析CA私鑰: {}", e))?;
        let crl = Arc::new(crl::CrlVerifier::new(SimpleCrl::new()));
        Ok(Certificate {
            ca_cert,
            ca_key,
            crl,
        })
    }

    /// 獲取RootCA憑證
    /// # 回傳
    /// * `&X509`: 返回 CA 憑證的引用
    pub fn get_ca_cert(&self) -> &X509 {
        &self.ca_cert
    }
    /// 獲取RootCA私鑰
    /// # 回傳
    /// * `&PKey<Private>`: 返回 CA 私鑰的引用
    pub fn get_ca_key(&self) -> &PKey<Private> {
        &self.ca_key
    }
    /// 獲取CRL驗證器
    /// # 回傳
    /// * `Arc<crl::CrlVerifier>`: 返回 CRL 驗證器的引用
    pub fn get_crl(&self) -> Arc<crl::CrlVerifier> {
        self.crl.clone()
    }
    /// 設定CRL驗證器
    /// # 參數
    /// * `crl`: 要設定的 CRL 驗證器
    /// # 回傳
    /// * `()`: 無返回值
    pub fn set_crl(&mut self, crl: Arc<crl::CrlVerifier>) {
        self.crl = crl;
    }
    /// 簽署 CSR 並返回簽署的憑證和 CA 憑證鏈
    /// # 參數
    /// * `csr`: 要簽署的 CSR (X509Req)
    /// * `days_valid`: 簽署的憑證有效天數
    /// # 回傳
    /// * `Ok((SignedCert, ChainCerts))`：簽署的憑證和 CA 憑證鏈
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
    pub fn sign_csr(&self, csr: &X509Req, days_valid: u32) -> CaResult<(SignedCert, ChainCerts)> {
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
        // TODO: 將簽發出去的憑證保留指紋及序號
        Ok((cert_der, chain_der))
    }
    /// 產生 CSR 與對應的私鑰
    /// # 參數
    /// * `key_bits`: RSA 金鑰長度 (e.g. 2048)
    /// * `country`, `state`, `locality`, `organization`, `common_name`: Subject 欄位
    /// * `subject_alt_names`: 要加入的 SAN DNS 名稱列表
    /// # 回傳
    /// * `Ok((private_key_pem, csr_pem))`：分別是私鑰和 CSR 的 PEM Bytes
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
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
    /// 儲存憑證和私鑰到指定的檔案
    /// # 參數
    /// * `filename`: 檔案名稱 (不含副檔名)
    /// * `cert`: 簽署的憑證
    /// * `private_key`: 私鑰
    /// # 回傳
    /// * `CaResult<()>`：返回結果，成功時為 Ok，失敗時為 Err
    pub fn save_cert(filename: &str, cert: SignedCert, private_key: PrivateKey) -> CaResult<()> {
        let key_path = Path::new("certs").join(format!("{}.key", filename));
        let cert_path = Path::new("certs").join(format!("{}.pem", filename));
        let mut f = fs::File::create(cert_path)?;
        let mut f_key = fs::File::create(key_path)?;
        let r = X509::from_der(&cert)
            .or_else(|_| X509::from_pem(&cert))
            .map_err(|e| format!("解析憑證失敗: {}", e))?;
        let r = String::from_utf8(r.to_pem()?)?;
        f.write_all(r.as_bytes())?;
        f_key.write_all(&private_key)?;
        Ok(())
    }
    /// 從指定的路徑載入憑證
    /// # 參數
    /// * `path`: 憑證檔案的路徑
    /// # 回傳
    /// * `CaResult<X509>`：返回憑證或錯誤
    pub fn load_cert<P: AsRef<Path>>(path: P) -> CaResult<X509> {
        let cert_pem = fs::read(path)?;
        X509::from_pem(&cert_pem)
            .or_else(|_| X509::from_der(&cert_pem))
            .map_err(|e| format!("無法解析憑證: {}", e).into())
    }
    /// 從指定的路徑載入私鑰
    /// # 參數
    /// * `path`: 私鑰檔案的路徑
    /// * `passphrase`: 私鑰的密碼短語 (如果有的話)
    /// # 回傳
    /// * `CaResult<PKey<Private>>`：返回私鑰或錯誤
    pub fn load_key<P: AsRef<Path>>(path: P, passphrase: Option<&str>) -> CaResult<PKey<Private>> {
        let key_pem = fs::read(path)?;
        if let Some(pass) = passphrase {
            PKey::private_key_from_pem_passphrase(&key_pem, pass.as_bytes())
                .map_err(|e| format!("無法解析私鑰: {}", e).into())
        } else {
            PKey::private_key_from_pem(&key_pem).map_err(|e| format!("無法解析私鑰: {}", e).into())
        }
    }
    /// 從憑證名稱載入憑證和私鑰
    /// # 參數
    /// * `cert_name`: 憑證名稱 (不含副檔名)
    /// * `passphrase`: 私鑰的密碼短語 (如果有的話)
    /// # 回傳
    /// * `CaResult<(PrivateKey, SignedCert)>`：返回私鑰和簽署的憑證
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
    pub fn cert_from_path(
        cert_name: &str,
        passphrase: Option<&str>,
    ) -> CaResult<(PrivateKey, SignedCert)> {
        let cert_path = Path::new("certs").join(format!("{}.pem", cert_name));
        if !cert_path.exists() {
            return Err(format!("憑證檔案 {} 不存在", cert_path.display()).into());
        }
        let key_path = Path::new("certs").join(format!("{}.key", cert_name));
        if !key_path.exists() {
            return Err(format!("金鑰檔案 {} 不存在", key_path.display()).into());
        }
        let ca_cert = Self::load_cert(cert_path)?;
        let ca_key = Self::load_key(key_path, passphrase)?;
        Ok((ca_key.private_key_to_pem_pkcs8()?, ca_cert.to_pem()?))
    }
    pub fn cert_fingerprint_sha256(pem: &[u8]) -> CaResult<String> {
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
    pub fn cert_serial_sha256(cert: X509) -> CaResult<String> {
        let serial = cert.serial_number();
        let digest = hash(MessageDigest::sha256(), serial.to_bn()?.to_vec().as_slice())?;
        let hex = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        Ok(hex)
    }
}
/// 建立一個 gRPC 的 CRL 檢查攔截器
/// # 參數
/// * `cert_handler`: 憑證處理器，用於檢查 CRL
/// # 回傳
/// * `impl Fn(Request<()>) -> Result<Request<()>, Status>`: 返回一個攔截器函數
fn make_crl_interceptor(
    cert_handler: Arc<Certificate>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone + Send + Sync + 'static {
    move |req: Request<()>| {
        let p_certs = req.peer_certs();
        let peer_certs_slice: Option<&[tonic::transport::CertificateDer]> =
            p_certs.as_ref().map(|arc_vec| arc_vec.as_ref().as_slice());
        if !cert_handler
            .get_crl()
            .after_connection_cert_check(peer_certs_slice)
        {
            Err(Status::permission_denied("Certificate was Revoked"))
        } else {
            Ok(req)
        }
    }
}

/// 啟動 gRPC 服務
/// # 參數
/// * `addr`: gRPC 服務的地址
/// * `cert_handler`: 憑證處理器，用於憑證簽署和 CRL 驗證
/// # 回傳
/// * `Result<(), Box<dyn std::error::Error>>`: 返回結果，成功時為 Ok，失敗時為 Err
pub async fn start_grpc(
    addr: SocketAddr,
    cert_handler: Arc<Certificate>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 設定 TLS
    let (key, cert) = Certificate::cert_from_path("ca_grpc", None)?;
    let identity = Identity::from_pem(cert, key);
    let tls = ServerTlsConfig::new().identity(identity).client_ca_root(
        tonic::transport::Certificate::from_pem(cert_handler.get_ca_cert().to_pem()?),
    );
    // ----------
    // 啟動健康檢查服務
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<ca_server::CaServer<MyCa>>()
        .await;
    // ----------
    let svc = ca_server::CaServer::with_interceptor(
        MyCa {
            cert: cert_handler.clone(),
        },
        make_crl_interceptor(cert_handler.clone()),
    );
    println!("gRPC server listening on {}", addr);
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl-C");
        println!("收到CtrlC,開始關閉gRPC...");
        health_reporter
            .set_not_serving::<ca_server::CaServer<MyCa>>()
            .await;
    };
    tonic::transport::Server::builder()
        .tls_config(tls)?
        .add_service(svc)
        .add_service(health_service)
        .serve_with_shutdown(addr, shutdown_signal)
        .await?;
    Ok(())
}
