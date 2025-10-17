use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub enum LoadStatus {
    #[serde(rename = "Load")]
    Load,
    #[serde(rename = "Notload")]
    Notload,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EnableStatus {
    #[serde(rename = "Enable")]
    Enable,
    #[serde(rename = "Disable")]
    Disable,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Module {
    #[serde(rename = "Name")]
    pub name:          String,
    #[serde(rename = "Version")]
    pub version:       String,
    #[serde(rename = "Description")]
    pub description:   String,
    #[serde(rename = "Author")]
    pub author:        String,
    #[serde(rename = "LoadStatus")]
    pub load_status:   LoadStatus,
    #[serde(rename = "EnableStatus")]
    pub enable_status: EnableStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleCollection {
    #[serde(rename = "Modules")]
    pub modules: HashMap<String, Module>,
    #[serde(rename = "Length")]
    pub length:  usize,
}

#[derive(Debug, MultipartForm)]
pub struct ModuleUploadForm {
    #[multipart(rename = "Modules")]
    pub modules: Vec<TempFile>,
}

#[derive(Debug, Serialize)]
pub struct ModuleResponse {
    #[serde(rename = "Module")]
    pub module: ModuleReport,
}

#[derive(Debug, Serialize)]
pub struct ModuleReport {
    #[serde(rename = "Load")]
    pub load:           Vec<String>,
    #[serde(rename = "Notload")]
    pub notload:        Vec<String>,
    #[serde(rename = "Load_Length")]
    pub load_length:    usize,
    #[serde(rename = "Notload_Length")]
    pub notload_length: usize,
}

impl ModuleReport {
    pub fn new(load: Vec<String>, notload: Vec<String>) -> Self {
        Self { load_length: load.len(), notload_length: notload.len(), load, notload }
    }
}

#[derive(Debug, Serialize)]
pub struct PutModuleResponse {
    #[serde(rename = "Module")]
    pub module: PutModuleReport,
}

#[derive(Debug, Serialize)]
pub struct PutModuleReport {
    #[serde(rename = "Success")]
    pub success:        Vec<String>,
    #[serde(rename = "Fail")]
    pub fail:           Vec<String>,
    #[serde(rename = "Success_Length")]
    pub success_length: usize,
    #[serde(rename = "Fail_Length")]
    pub fail_length:    usize,
}

#[derive(Debug, Deserialize)]
pub struct DeleteModuleRequest {
    #[serde(rename = "Modules")]
    pub modules: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteModuleResponse {
    #[serde(rename = "Module")]
    pub module: DeleteModuleReport,
}

#[derive(Debug, Serialize)]
pub struct DeleteModuleReport {
    #[serde(rename = "Delete")]
    pub delete:            Vec<String>,
    #[serde(rename = "Notdelete")]
    pub not_delete:        Vec<String>,
    #[serde(rename = "Delete_Length")]
    pub delete_length:     usize,
    #[serde(rename = "Notdelete_Length")]
    pub not_delete_length: usize,
}
