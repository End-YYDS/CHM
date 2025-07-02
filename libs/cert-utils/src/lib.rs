use std::{fs, io::Write, net::IpAddr, path::Path};

use grpc::{crl::ListCrlEntriesResponse, prost::Message};
use openssl::{
    bn::BigNum,
    hash::{hash, MessageDigest},
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Verifier,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
        X509Builder, X509NameBuilder, X509ReqBuilder, X509,
    },
};
use project_const::ProjectConst;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Debug)]
pub struct CertUtils;
impl CertUtils {
    pub fn generate_rsa_keypair(key_bits: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let rsa = Rsa::generate(key_bits)?;
        let private_key_pem = rsa.private_key_to_pem()?;
        let public_key_pem = rsa.public_key_to_pem()?;

        Ok((private_key_pem, public_key_pem))
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
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        //  產生RSA私鑰
        let (key_pem, _) = Self::generate_rsa_keypair(key_bits)?;
        let private_key = PKey::private_key_from_pem(&key_pem)?;
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
    #[allow(clippy::too_many_arguments)]
    /// 產生自簽名憑證
    /// # 參數
    /// * `csr`: CSR 的 PEM Bytes
    ///
    pub fn generate_self_signed_cert(
        bits: u32,
        country: &str,
        state: &str,
        locality: &str,
        org: &str,
        cn: &str,
        san: &[&str],
        days: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (key_pem, _) = Self::generate_rsa_keypair(bits)?;
        let key = PKey::private_key_from_pem(&key_pem)?;
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        let mut bn = BigNum::new()?;
        bn.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(days)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        let mut name_b = X509NameBuilder::new()?;
        for &(field, value) in &[
            ("C", country),
            ("ST", state),
            ("L", locality),
            ("O", org),
            ("CN", cn),
        ] {
            name_b.append_entry_by_text(field, value)?;
        }
        let name = name_b.build();
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        if !san.is_empty() {
            let mut san_b = SubjectAlternativeName::new();
            for &entry in san {
                if entry.parse::<IpAddr>().is_ok() {
                    san_b.ip(entry);
                } else {
                    san_b.dns(entry);
                }
            }
            let ext = san_b.build(&builder.x509v3_context(None, None))?;
            builder.append_extension(ext)?;
        }
        builder.sign(&key, MessageDigest::sha256())?;
        let cert_pem = builder.build().to_pem()?;
        Ok((key_pem, cert_pem))
    }
    /// 儲存憑證和私鑰到指定的檔案
    /// # 參數
    /// * `filename`: 檔案名稱 (不含副檔名)
    /// * `cert`: 簽署的憑證
    /// * `private_key`: 私鑰
    /// # 回傳
    /// * `CaResult<()>`：返回結果，成功時為 Ok，失敗時為 Err
    pub fn save_cert(filename: &str, private_key: Vec<u8>, cert: Vec<u8>) -> Result<()> {
        let save_path = ProjectConst::certs_path();
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
    pub fn load_cert<P: AsRef<Path>>(path: P) -> Result<X509> {
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
    pub fn load_key<P: AsRef<Path>>(path: P, passphrase: Option<&str>) -> Result<PKey<Private>> {
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
    pub fn cert_from_path(cert_name: &str, passphrase: Option<&str>) -> Result<(Vec<u8>, Vec<u8>)> {
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
    pub fn cert_fingerprint_sha256(cert: &X509) -> Result<String> {
        let der = cert.to_der()?;
        let digest = hash(MessageDigest::sha256(), &der)?;
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        Ok(hex)
    }
    pub fn cert_serial_sha256(cert: &X509) -> Result<String> {
        let serial = cert.serial_number();
        let digest = hash(MessageDigest::sha256(), serial.to_bn()?.to_vec().as_slice())?;
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        Ok(hex)
    }
    /// 驗證 CRL 回應的簽名是否來自於指定的 CA
    pub fn verify_crl_signature(
        ca_cert: &X509,
        resp: &ListCrlEntriesResponse,
    ) -> std::result::Result<(), String> {
        let signature = resp.signature.as_slice();
        let mut clean = resp.clone();
        clean.signature = Vec::new();
        let raw = Message::encode_to_vec(&clean);
        let pubkey = ca_cert
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
}
