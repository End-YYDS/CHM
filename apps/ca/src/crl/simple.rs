use chrono::{DateTime, Utc};
use openssl::{
    hash::{hash, MessageDigest},
    x509::X509,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs};

use crate::CaResult;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct CrlData {
    pub serial: String,
    pub reason: String,
    pub date: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleCrl {
    revoked: HashSet<CrlData>,
}

impl Default for SimpleCrl {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleCrl {
    pub fn new() -> Self {
        SimpleCrl {
            revoked: HashSet::new(),
        }
    }
    /// 從 TOML 檔讀取 revoked hex 清單
    pub fn load_from_file(path: &str) -> CaResult<Self> {
        let data = fs::read_to_string(path)?;
        let toml_crl: SimpleCrl = toml::from_str(&data)?;
        Ok(toml_crl)
    }

    pub fn save_to_file(&self, path: &str) -> CaResult<()> {
        let toml_crl = toml::to_string_pretty(&self)?;
        fs::write(path, toml_crl)?;
        Ok(())
    }

    fn cert_serial_sha256(cert: &X509) -> CaResult<String> {
        let serial = cert.serial_number();
        let digest = hash(MessageDigest::sha256(), serial.to_bn()?.to_vec().as_slice())?;
        let hex = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        Ok(hex)
    }

    /// 是否被撤銷
    pub fn is_revoked_cert(&self, cert: &X509) -> CaResult<bool> {
        let hex = Self::cert_serial_sha256(cert)?;
        Ok(self
            .revoked
            .iter()
            .any(|entry: &CrlData| entry.serial == hex))
    }
    pub fn add_revoked_cert(
        &mut self,
        cert: &X509,
        reason: String,
        date: DateTime<Utc>,
    ) -> CaResult<()> {
        let hex = Self::cert_serial_sha256(cert)?;
        let to_remove: Vec<CrlData> = self
            .revoked
            .iter()
            .filter(|entry| entry.serial == hex)
            .cloned()
            .collect();
        for old in to_remove {
            self.revoked.remove(&old);
        }
        let new_entry = CrlData {
            serial: hex,
            reason,
            date,
        };
        self.revoked.insert(new_entry);
        Ok(())
    }
    pub fn remove_revoked_cert(&mut self, cert: &X509) -> CaResult<()> {
        let hex = Self::cert_serial_sha256(cert)?;
        let to_remove: Vec<CrlData> = self
            .revoked
            .iter()
            .filter(|entry| entry.serial == hex)
            .cloned()
            .collect();

        for old in to_remove {
            self.revoked.remove(&old);
        }
        Ok(())
    }
    pub fn clear(&mut self) {
        self.revoked.clear();
    }
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
    pub fn len(&self) -> usize {
        self.revoked.len()
    }
    /// 如果只是想拿到所有 serial 字符串列表，也可以这样写
    pub fn revoked_list_serials(&self) -> Vec<String> {
        self.revoked
            .iter()
            .map(|entry| entry.serial.clone())
            .collect()
    }

    /// 如果想拿到所有完整的 CrlData
    pub fn revoked_list_all(&self) -> Vec<CrlData> {
        self.revoked.iter().cloned().collect()
    }
    pub fn from_revoked_list(revoked: Vec<CrlData>) -> Self {
        SimpleCrl {
            revoked: revoked.into_iter().collect(),
        }
    }
}
