use std::path::PathBuf;
pub extern crate uuid;
pub struct ProjectConst;
impl ProjectConst {
    pub const SOFTWARE_NAME: &'static str = "CHM";
    pub const SOFTWARE_VERSION: &'static str = env!("CARGO_PKG_VERSION");
    pub const SOFTWARE_DESCRIPTION: &'static str = env!("CARGO_PKG_DESCRIPTION");
    pub const SOFTWARE_PORT: u16 = 11209;
    pub const SOFTWARE_AUTHORS: &'static str = env!("CARGO_PKG_AUTHORS");
    pub const SOFTWARE_GIT_COMMIT: &'static str = env!("CARGO_PKG_HOMEPAGE");
    pub const SAVE_DIR: &'static str = "/etc";
    pub const PROJECT_NAME: &'static str = "CHM";
    pub const CONFIG_DIR: &'static str = "config";
    pub const CERTS_DIR: &'static str = "certs";
    pub const DATA_DIR: &'static str = "data";
    pub const DB_DIR: &'static str = "db";

    pub fn is_debug() -> bool {
        cfg!(debug_assertions)
    }
    pub fn release_save_dir() -> PathBuf {
        PathBuf::from(Self::SAVE_DIR).join(Self::PROJECT_NAME)
    }
    pub fn certs_path() -> PathBuf {
        let dir = if Self::is_debug() {
            PathBuf::from(Self::CERTS_DIR)
        } else {
            Self::release_save_dir().join(Self::CERTS_DIR)
        };
        if dir.exists() {
            dir
        } else {
            std::fs::create_dir_all(&dir).expect("無法創建憑證目錄");
            dir
        }
    }
    pub fn config_path() -> PathBuf {
        let dir = if Self::is_debug() {
            PathBuf::from(Self::CONFIG_DIR)
        } else {
            Self::release_save_dir().join(Self::CONFIG_DIR)
        };
        if dir.exists() {
            dir
        } else {
            std::fs::create_dir_all(&dir).expect("無法創建配置目錄");
            dir
        }
    }
    pub fn data_path() -> PathBuf {
        let dir = if Self::is_debug() {
            PathBuf::from(Self::DATA_DIR)
        } else {
            Self::release_save_dir().join(Self::DATA_DIR)
        };
        if dir.exists() {
            dir
        } else {
            std::fs::create_dir_all(&dir).expect("無法創建數據目錄");
            dir
        }
    }
    pub fn db_path() -> PathBuf {
        let dir = if Self::is_debug() {
            PathBuf::from(Self::DB_DIR)
        } else {
            Self::release_save_dir().join(Self::DB_DIR)
        };
        if dir.exists() {
            dir
        } else {
            std::fs::create_dir_all(&dir).expect("無法創建數據庫目錄");
            dir
        }
    }
}
