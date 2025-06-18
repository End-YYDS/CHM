use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use grpc::tonic::transport::CertificateDer;
use openssl::x509::X509;
use rsntp::SntpClient;

use crate::cert::crl::SimpleCrl;

#[derive(Debug)]
pub struct CrlVerifier {
    crl: Mutex<SimpleCrl>,
}

impl CrlVerifier {
    /// 建構一個 CRL 驗證器
    /// # 參數
    /// * `crl`: 一個 `SimpleCrl` 實例，包含撤銷的證書資訊
    /// # 回傳
    /// * 一個 `CrlVerifier` 實例，內部使用 `Mutex` 保護 `SimpleCrl` 的可變性
    pub fn new(crl: SimpleCrl) -> Self {
        CrlVerifier {
            crl: Mutex::new(crl),
        }
    }
    /// 從NTP伺服器取得當前的 UTC 時間
    /// # 回傳
    /// * 一個 `DateTime<Utc>` 實例，表示當前的 UTC 時間
    pub fn get_utc() -> DateTime<Utc> {
        let client = SntpClient::new();
        let result = client.synchronize("pool.ntp.org").unwrap();
        let local_time: DateTime<Utc> = result.datetime().into_chrono_datetime().unwrap();
        local_time
    }
    /// 取得SimpleCrl可變
    /// # 回傳
    /// * 一個 `MutexGuard<SimpleCrl>`，用於安全地訪問和修改 CRL
    pub fn mut_crl(&self) -> MutexGuard<SimpleCrl> {
        self.crl.lock().expect("Failed to lock CRL mutex")
    }
    /// 檢查一個證書是否被撤銷
    /// # 參數
    /// * `cert`: 一個 `X509` 證書實例
    /// # 回傳
    /// * 如果證書被撤銷，則返回 `true`，否則返回 `false`
    pub fn is_revoked(&self, cert: &openssl::x509::X509) -> bool {
        self.crl
            .lock()
            .unwrap()
            .is_revoked_cert(cert)
            .unwrap_or(false)
    }
    /// 當有新的連線進來時，取得 client 端送過來的 peer certificates (DER 格式)
    /// 如果有任何一張 cert 的 serial number 在 CRL 裡，就回 false (表示被 revoke) 否則回 true
    /// # 參數
    /// * `peer_certs`: 一個可選的切片，包含來自 client 的證書（DER 格式）
    /// # 回傳
    /// * 如果所有證書都未被撤銷，則返回 `true`，否則返回 `false`
    pub fn after_connection_cert_check(&self, peer_certs: Option<&[CertificateDer]>) -> bool {
        let certs = match peer_certs {
            Some(slice) => slice,
            None => return true,
        };
        for cert_der in certs.iter() {
            let der_bytes: &[u8] = cert_der.as_ref();
            if let Ok(x509) = X509::from_der(der_bytes) {
                if let Ok(is_revoked) = self.crl.lock().unwrap().is_revoked_cert(&x509) {
                    if is_revoked {
                        return false;
                    }
                }
            }
        }
        true
    }
}
