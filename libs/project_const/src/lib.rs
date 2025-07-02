use std::path::PathBuf;

pub struct ProjectConst;
impl ProjectConst {
    pub const SAVE_DIR: &str = "/etc";
    pub const PROJECT_NAME: &str = "CHM";
    pub const CONFIG_DIR: &str = "config";
    pub const CERTS_DIR: &str = "certs";
    pub const DATA_DIR: &str = "data";

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
}
