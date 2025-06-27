use config_loader::PROJECT;
use grpc::{crl::ListCrlEntriesResponse, prost::Message};
use openssl::{
    asn1::Asn1Integer,
    bn::{BigNum, MsbOption},
    hash::{hash, MessageDigest},
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::{Signer, Verifier},
    symm::Cipher,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
        X509Builder, X509NameBuilder, X509Req, X509ReqBuilder, X509,
    },
};
use std::net::IpAddr;
use std::path::Path;
use std::{fs, sync::Arc};
use std::{io::Write, path::PathBuf};

use crate::{
    cert::crl::{self, CrlVerifier},
    globals::GlobalConfig,
    CaResult, ChainCerts, CsrCert, PrivateKey, SignedCert,
};
#[allow(unused)]
/// 憑證處理器，負責載入 CA 憑證和金鑰，簽署 CSR，並提供 CRL 驗證功能
pub struct CertificateProcess {
    /// CA 憑證
    ca_cert: X509,
    /// CA 私鑰
    ca_key: PKey<Private>,
    /// CRL 驗證器
    crl: Arc<crl::CrlVerifier>,
    store: Arc<dyn crate::cert::store::CertificateStore>,
}
// #[allow(unused)]
impl CertificateProcess {
    /// 從指定的憑證和金鑰檔案載入 CA 憑證和金鑰
    /// # 參數
    /// * `cert_path`: CA 憑證檔案路徑
    /// * `key_path`: CA 金鑰檔案路徑
    /// * `passphrase`: 金鑰的密碼短語
    /// # 回傳
    /// * `Ok(CertificateProcess)`：載入成功，返回憑證和金鑰
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
    pub async fn load<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        passphrase: &str,
        crl_update_interval: std::time::Duration,
        store: Arc<dyn crate::cert::store::CertificateStore>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_pem = fs::read(&cert_path)
            .or_else(|_| fs::read("certs/rootCA.pem"))
            .or_else(|_| fs::read("certs/test_root_ca.pem"))?;
        let key_pem = fs::read(&key_path)
            .or_else(|_| fs::read("certs/rootCA.key"))
            .or_else(|_| fs::read("certs/test_root_ca.key"))?;
        let ca_cert = X509::from_pem(&cert_pem)
            .or_else(|_| X509::from_der(&cert_pem))
            .map_err(|e| format!("無法解析CA憑證: {e}"))?;
        let ca_key = if passphrase.is_empty() {
            PKey::private_key_from_pem(&key_pem)
        } else {
            PKey::private_key_from_pem_passphrase(&key_pem, passphrase.as_bytes())
        }
        .map_err(|e| format!("無法解析CA私鑰: {e}"))?;
        let crl = Arc::new(
            CrlVerifier::new(
                store.clone(),
                chrono::Duration::from_std(crl_update_interval)
                    .expect("Invalid CRL update interval"),
            )
            .await?,
        );
        Ok(CertificateProcess {
            ca_cert,
            ca_key,
            crl,
            store,
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

    pub fn get_store(&self) -> Arc<dyn crate::cert::store::CertificateStore> {
        self.store.clone()
    }

    pub fn set_store(&mut self, store: Arc<dyn crate::cert::store::CertificateStore>) {
        self.store = store;
    }
    /// 簽署 CSR 並返回簽署的憑證和 CA 憑證鏈
    /// # 參數
    /// * `csr`: 要簽署的 CSR (X509Req)
    /// * `days_valid`: 簽署的憑證有效天數
    /// # 回傳
    /// * `Ok((SignedCert, ChainCerts))`：簽署的憑證和 CA 憑證鏈
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
    pub async fn sign_csr(
        &self,
        csr: &X509Req,
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
        let mut bn = BigNum::new()?;
        let bits = GlobalConfig::read().await.settings.certificate.bits;
        bn.rand(bits, MsbOption::ONE, false)?;
        let serial = Asn1Integer::from_bn(&bn)?;
        builder.set_serial_number(&serial)?;
        builder.sign(&self.ca_key, MessageDigest::sha256())?;
        let leaf = builder.build();
        let cert_der = leaf.to_der()?;
        let chain_der = vec![self.ca_cert.to_der()?];
        self.store.insert(leaf).await?;
        Ok((cert_der, chain_der))
    }
    /// 產生 Root CA 憑證和對應的私鑰
    /// # 參數
    /// * `key_bits`: RSA 金鑰長度 (e.g. 204
    /// * `country`, `state`, `locality`, `organization`, `common_name`: Subject 欄位
    /// * `days_valid`: 憑證有效天數
    /// * `passphrase`: 可選的私鑰密碼短語
    /// * `bits`: 用於序列號的位數
    /// # 回傳
    /// * `Ok((private_key_pem, cert_pem))`：分別是私鑰和憑證的 PEM Bytes
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
    /// # 注意
    /// 這個函式會產生一個新的 Root CA
    #[allow(clippy::too_many_arguments)]
    pub fn generate_root_ca(
        key_bits: u32,
        country: &str,
        state: &str,
        locality: &str,
        organization: &str,
        common_name: &str,
        days_valid: u32,
        passphrase: Option<&[u8]>,
        bits: i32,
    ) -> CaResult<(PrivateKey, CsrCert)> {
        // 1. 產生 RSA 私鑰
        let rsa = Rsa::generate(key_bits)?;
        let pkey = PKey::from_rsa(rsa)?;

        // 2. 建立 Subject／Issuer Name
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", country)?;
        name_builder.append_entry_by_text("ST", state)?;
        name_builder.append_entry_by_text("L", locality)?;
        name_builder.append_entry_by_text("O", organization)?;
        name_builder.append_entry_by_text("CN", common_name)?;
        let name = name_builder.build();
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        let mut bn = BigNum::new()?;
        bn.rand(bits, MsbOption::ONE, false)?;
        let serial = Asn1Integer::from_bn(&bn)?;
        builder.set_serial_number(&serial)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(days_valid)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;
        builder.append_extension(BasicConstraints::new().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .key_cert_sign()
                .critical()
                .crl_sign()
                .build()?,
        )?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
        )?;
        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .issuer(false)
                .build(&builder.x509v3_context(None, None))?,
        )?;
        builder.sign(&pkey, MessageDigest::sha256())?;
        let cert = builder.build();
        let key_pem = if let Some(pw) = passphrase {
            pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pw)?
        } else {
            pkey.private_key_to_pem_pkcs8()?
        };
        let cert_pem = cert.to_pem()?;
        Ok((key_pem, cert_pem))
    }
    /// 產生中介 CA 憑證和對應的私鑰
    /// # 參數
    /// * `key_bits`: RSA 金鑰長度 (e.g. 2048)
    /// * `country`, `state`, `locality`, `organization`, `common_name`: Subject 欄位
    /// * `days_valid`: 憑證有效天數
    /// * `bits`: 用於序列號的位數
    /// * `pathlen`: 可選的 BasicConstraints 路徑長度限制
    /// * `passphrase`: 可選的私鑰密碼短語
    /// # 回傳
    /// * `Ok((private_key_pem, cert_pem))`：分別是私鑰和憑證的 PEM Bytes
    /// * `Err(e)`：若任何步驟失敗，回傳錯誤
    #[allow(clippy::too_many_arguments)]
    pub fn generate_intermediate_ca(
        &self,
        key_bits: u32,
        country: &str,
        state: &str,
        locality: &str,
        organization: &str,
        common_name: &str,
        days_valid: u32,
        bits: i32,
        pathlen: Option<u32>,
        passphrase: Option<&[u8]>,
    ) -> CaResult<(PrivateKey, CsrCert)> {
        let rsa = Rsa::generate(key_bits)?;
        let pkey = PKey::from_rsa(rsa)?;
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", country)?;
        name_builder.append_entry_by_text("ST", state)?;
        name_builder.append_entry_by_text("L", locality)?;
        name_builder.append_entry_by_text("O", organization)?;
        name_builder.append_entry_by_text("CN", common_name)?;
        let name = name_builder.build();
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        let mut bn = BigNum::new()?;
        bn.rand(bits, MsbOption::ONE, false)?;
        let serial = Asn1Integer::from_bn(&bn)?;
        builder.set_serial_number(&serial)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(days_valid)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.ca_cert.subject_name())?;
        builder.set_pubkey(&pkey)?;
        let mut binding = BasicConstraints::new();
        let mut bc = binding.ca();
        if let Some(pl) = pathlen {
            bc = bc.pathlen(pl);
        }
        builder.append_extension(bc.build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .key_cert_sign()
                .crl_sign()
                .critical()
                .build()?,
        )?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
        )?;
        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .issuer(true)
                .build(&builder.x509v3_context(Some(&self.ca_cert), None))?,
        )?;
        builder.sign(&self.ca_key, MessageDigest::sha256())?;
        let cert = builder.build();
        let cert_pem = cert.to_pem()?;
        let key_pem = if let Some(pw) = passphrase {
            pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pw)?
        } else {
            pkey.private_key_to_pem_pkcs8()?
        };

        Ok((key_pem, cert_pem))
    }
    /// 用 CA 私鑰對 raw protobuf bytes 做 SHA256-with-RSA 簽名
    pub fn sign_crl(&self, data: &[u8]) -> CaResult<Vec<u8>> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.ca_key)
            .map_err(|e| format!("無法建立簽名器: {e}"))?;
        signer
            .update(data)
            .map_err(|e| format!("簽名資料失敗: {e}"))?;
        let sig = signer
            .sign_to_vec()
            .map_err(|e| format!("生成簽名失敗: {e}"))?;
        Ok(sig)
    }
    /// 驗證 CRL 回應的簽名是否來自於指定的 CA
    pub fn verify_crl_signature(&self, resp: &ListCrlEntriesResponse) -> Result<(), String> {
        let signature = resp.signature.as_slice();
        let mut clean = resp.clone();
        clean.signature = Vec::new();
        let raw = Message::encode_to_vec(&clean);
        let pubkey = self
            .ca_cert
            .public_key()
            .map_err(|e| format!("取公鑰失敗: {e}"))?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey)
            .map_err(|e| format!("建立 Verifier 失敗: {e}"))?;
        verifier
            .update(&raw)
            .map_err(|e| format!("Verifier update 失敗: {e}"))?;
        if verifier
            .verify(signature)
            .map_err(|e| format!("執行 verify 失敗: {e}"))?
        {
            Ok(())
        } else {
            Err("簽名驗證失敗：簽章不符".into())
        }
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
    ) -> CaResult<(PrivateKey, CsrCert)> {
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
    pub fn save_cert(filename: &str, private_key: PrivateKey, cert: SignedCert) -> CaResult<()> {
        let certs_path = Path::new("certs");
        let save_path = if cfg!(debug_assertions) {
            certs_path.to_path_buf()
        } else {
            PathBuf::from("/etc").join(PROJECT.2).join(certs_path) //TODO: 安裝腳本安裝時注意資料夾權限問題
        };
        let key_path = save_path.join(format!("{filename}.key"));
        let cert_path = save_path.join(format!("{filename}.pem"));
        if !save_path.exists() {
            fs::create_dir_all(save_path)?;
        }
        let mut f = fs::File::create(cert_path)?;
        let mut f_key = fs::File::create(key_path)?;
        let r = X509::from_der(&cert)
            .or_else(|_| X509::from_pem(&cert))
            .map_err(|e| format!("解析憑證失敗: {e}"))?;
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
            .map_err(|e| format!("無法解析憑證: {e}").into())
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
                .map_err(|e| format!("無法解析私鑰: {e}").into())
        } else {
            PKey::private_key_from_pem(&key_pem).map_err(|e| format!("無法解析私鑰: {e}").into())
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
        let cert_path = Path::new("certs").join(format!("{cert_name}.pem"));
        if !cert_path.exists() {
            return Err(format!("憑證檔案 {} 不存在", cert_path.display()).into());
        }
        let key_path = Path::new("certs").join(format!("{cert_name}.key"));
        if !key_path.exists() {
            return Err(format!("金鑰檔案 {} 不存在", key_path.display()).into());
        }
        let ca_cert = Self::load_cert(cert_path)?;
        let ca_key = Self::load_key(key_path, passphrase)?;
        Ok((ca_key.private_key_to_pem_pkcs8()?, ca_cert.to_pem()?))
    }
    pub fn cert_fingerprint_sha256(cert: &X509) -> CaResult<String> {
        let der = cert.to_der()?;
        let digest = hash(MessageDigest::sha256(), &der)?;
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        Ok(hex)
    }
    pub fn cert_serial_sha256(cert: &X509) -> CaResult<String> {
        let serial = cert.serial_number();
        let digest = hash(MessageDigest::sha256(), serial.to_bn()?.to_vec().as_slice())?;
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        Ok(hex)
    }
    pub fn is_controller_cert(
        &self,
        cert: &X509,
        controller_args: (String, String),
    ) -> CaResult<bool> {
        let serial = CertificateProcess::cert_serial_sha256(cert)?;
        let fingerprint = CertificateProcess::cert_fingerprint_sha256(cert)?;
        Ok(controller_args.0 == serial && controller_args.1 == fingerprint)
    }
}
