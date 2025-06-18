use chrono::{DateTime, Utc};
use openssl::{
    hash::{hash, MessageDigest},
    x509::X509,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs};

use crate::CaResult;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
/// 撤銷的憑證資料
pub struct CrlData {
    /// 憑證序列號的 SHA-256 hex 字符串
    pub serial: String,
    /// 撤銷原因
    pub reason: String,
    /// 撤銷日期
    pub date: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
/// 簡單的 CRL (Certificate Revocation List) 實現
pub struct SimpleCrl {
    /// 撤銷的憑證資料集合
    revoked: HashSet<CrlData>,
}

impl Default for SimpleCrl {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleCrl {
    /// 建立一個新的 SimpleCrl 實例
    pub fn new() -> Self {
        SimpleCrl {
            revoked: HashSet::new(),
        }
    }
    /// 從 TOML 檔讀取 revoked hex 清單
    /// # 參數
    /// * `path` - 檔案路徑
    /// # 回傳
    /// * `CaResult<Self>` - 返回 SimpleCrl 實例或錯誤
    pub fn load_from_file(path: &str) -> CaResult<Self> {
        let data = fs::read_to_string(path)?;
        let toml_crl: SimpleCrl = toml::from_str(&data)?;
        Ok(toml_crl)
    }
    /// 將 revoked hex 清單儲存到 TOML 檔
    /// # 參數
    /// * `path` - 檔案路徑
    /// # 回傳
    /// * `CaResult<()>` - 返回結果，成功時為 Ok，失敗時為 Err
    pub fn save_to_file(&self, path: &str) -> CaResult<()> {
        let toml_crl = toml::to_string_pretty(&self)?;
        fs::write(path, toml_crl)?;
        Ok(())
    }
    /// 計算憑證序列號的 SHA-256 hex 字符串
    /// # 參數
    /// * `cert` - X509 憑證
    /// # 回傳
    /// * `CaResult<String>` - 返回序列號的 SHA-256 hex 字符串或錯誤
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
    /// # 參數
    /// * `cert` - X509 憑證
    /// # 回傳
    /// * `CaResult<bool>` - 返回是否被撤銷的結果
    pub fn is_revoked_cert(&self, cert: &X509) -> CaResult<bool> {
        let hex = Self::cert_serial_sha256(cert)?;
        Ok(self
            .revoked
            .iter()
            .any(|entry: &CrlData| entry.serial == hex))
    }
    /// 添加憑證至撤銷清單
    /// # 參數
    /// * `cert` - X509 憑證
    /// * `reason` - 撤銷原因
    /// * `date` - 撤銷日期
    /// # 回傳
    /// * `CaResult<()>` - 返回結果，成功時為 Ok，失敗時為 Err
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
    /// 移除撤銷的憑證
    /// # 參數
    /// * `cert` - X509 憑證
    /// # 回傳
    /// * `CaResult<()>` - 返回結果，成功時為 Ok，失敗時為 Err
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
    /// 清空撤銷清單
    pub fn clear(&mut self) {
        self.revoked.clear();
    }
    /// 是否為空
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
    /// 撤銷清單的長度
    pub fn len(&self) -> usize {
        self.revoked.len()
    }
    /// 如果只是想拿到所有 serial 字符串列表，也可以这样写
    /// # 回傳
    /// * `Vec<String>` - 返回撤銷的憑證序列號列表
    pub fn revoked_list_serials(&self) -> Vec<String> {
        self.revoked
            .iter()
            .map(|entry| entry.serial.clone())
            .collect()
    }

    /// 如果想拿到所有完整的 CrlData
    /// # 回傳
    /// * `Vec<CrlData>` - 返回撤銷的憑證資料列表
    pub fn revoked_list_all(&self) -> Vec<CrlData> {
        self.revoked.iter().cloned().collect()
    }
    /// 從撤銷列表建立 SimpleCrl
    /// # 參數
    /// * `revoked` - 撤銷的憑證資料列表
    /// # 回傳
    /// * `Self` - 返回新的 SimpleCrl 實例
    pub fn from_revoked_list(revoked: Vec<CrlData>) -> Self {
        SimpleCrl {
            revoked: revoked.into_iter().collect(),
        }
    }
}
