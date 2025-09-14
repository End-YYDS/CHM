use std::path::PathBuf;

pub struct ProjectConst;
impl ProjectConst {
    pub const SAVE_DIR: &'static str = "/etc";
    pub const PROJECT_NAME: &'static str = "CHM";
    pub const CONFIG_DIR: &'static str = "config";
    pub const CERTS_DIR: &'static str = "certs";
    pub const DATA_DIR: &'static str = "data";
    pub const DB_DIR: &'static str = "db";

    fn is_debug() -> bool {
        cfg!(debug_assertions)
    }
    pub fn release_save_dir() -> PathBuf {
        PathBuf::from(Self::SAVE_DIR).join(Self::PROJECT_NAME)
    }
    pub fn certs_path() -> PathBuf {
        if Self::is_debug() {
            PathBuf::from(Self::CERTS_DIR)
        } else {
            Self::release_save_dir().join(Self::CERTS_DIR)
        }
    }
    pub fn config_path() -> PathBuf {
        if Self::is_debug() {
            PathBuf::from(Self::CONFIG_DIR)
        } else {
            Self::release_save_dir().join(Self::CONFIG_DIR)
        }
    }
    pub fn data_path() -> PathBuf {
        if Self::is_debug() {
            PathBuf::from(Self::DATA_DIR)
        } else {
            Self::release_save_dir().join(Self::DATA_DIR)
        }
    }
    pub fn db_path() -> PathBuf {
        if Self::is_debug() {
            PathBuf::from(Self::DB_DIR)
        } else {
            Self::release_save_dir().join(Self::DB_DIR)
        }
    }
}
