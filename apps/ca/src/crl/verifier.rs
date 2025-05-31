use std::{
    sync::{Arc, Mutex, MutexGuard},
};

use chrono::{DateTime, Utc};
use rsntp::SntpClient;
use tonic::transport::CertificateDer;

use crate::crl::SimpleCrl;

#[derive(Debug)]
pub struct CrlVerifier {
    crl: Mutex<SimpleCrl>,
}

impl CrlVerifier {
    pub fn new(crl: SimpleCrl) -> Self {
        CrlVerifier {
            crl: Mutex::new(crl),
        }
    }
    pub fn get_utc() -> DateTime<Utc> {
        let client = SntpClient::new();
        let result = client.synchronize("pool.ntp.org").unwrap();
        let local_time: DateTime<Utc> = result.datetime().into_chrono_datetime().unwrap();
        local_time
    }
    pub fn mut_crl(&self) -> MutexGuard<SimpleCrl> {
        self.crl.lock().expect("Failed to lock CRL mutex")
    }

    pub fn is_revoked_cert(&self, cert: &openssl::x509::X509) -> bool {
        self.crl
            .lock()
            .unwrap()
            .is_revoked_cert(cert)
            .unwrap_or(false)
    }
    // TODO: 檢查連線的憑證是否被撤銷
    pub fn after_connection_cert_check(&self, cert_vec: Option<Arc<Vec<CertificateDer>>>) -> bool {
        if let Some(cert_vec_arc) = cert_vec {
            if let Some(left_cert) = cert_vec_arc.first() {
                dbg!(left_cert);
            }
        }
        true
    }
}
