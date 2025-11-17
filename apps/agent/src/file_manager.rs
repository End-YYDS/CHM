// Functions: get_pdir

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};

use crate::{
    execute_host_body, make_sysinfo_command_with_argument, send_to_hostd, shell_quote, ReturnInfo,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Clone, Copy)]
pub enum SizeUnit {
    B,
    KB,
    MB,
    GB,
}

impl SizeUnit {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "B" => Some(SizeUnit::B),
            "KB" => Some(SizeUnit::KB),
            "MB" => Some(SizeUnit::MB),
            "GB" => Some(SizeUnit::GB),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct DirectoryEntry {
    pub size:     f64,
    pub unit:     SizeUnit,
    pub owner:    String,
    pub mode:     String,
    pub modified: String,
}

#[derive(Debug)]
pub struct ParentDirectory {
    pub files:  BTreeMap<String, DirectoryEntry>,
    pub length: usize,
}

#[derive(Deserialize)]
struct GetPdirArgument {
    #[serde(rename = "Directory")]
    directory: Option<String>,
}

#[derive(Serialize)]
struct GetPdirRequest<'a> {
    #[serde(rename = "Directory")]
    directory: &'a str,
}

#[derive(Deserialize)]
struct ParentDirectoryDto {
    #[serde(rename = "Files")]
    files:  BTreeMap<String, DirectoryEntryDto>,
    #[serde(rename = "Length")]
    length: usize,
}

#[derive(Deserialize)]
struct DirectoryEntryDto {
    #[serde(rename = "Size")]
    size:     f64,
    #[serde(rename = "Unit")]
    unit:     String,
    #[serde(rename = "Owner")]
    owner:    String,
    #[serde(rename = "Mode")]
    mode:     String,
    #[serde(rename = "Modified")]
    modified: String,
}

pub fn pdir_info_structured(argument: Option<&str>) -> io::Result<ParentDirectory> {
    let directory = parse_pdir_argument(argument)?;
    let payload = GetPdirRequest { directory: &directory };
    let payload_json = serde_json::to_string(&payload).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to encode get_pdir payload: {}", e),
        )
    })?;

    let cmd = make_sysinfo_command_with_argument("pdir_status", &payload_json);
    let output = send_to_hostd(&cmd)?;

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::other(info.message));
    }

    let dto: ParentDirectoryDto = serde_json::from_str(&output).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse directory info JSON: {}", e),
        )
    })?;

    convert_parent_directory(dto)
}

fn parse_pdir_argument(argument: Option<&str>) -> io::Result<String> {
    if let Some(raw) = argument {
        let dto: GetPdirArgument = serde_json::from_str(raw).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("get_pdir argument parse error: {}", e),
            )
        })?;
        let directory = dto.directory.unwrap_or_else(|| "/".to_string());
        let normalized = directory.trim();
        if normalized.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(normalized.to_string())
        }
    } else {
        Ok("/".to_string())
    }
}

fn convert_parent_directory(dto: ParentDirectoryDto) -> io::Result<ParentDirectory> {
    let mut files = BTreeMap::new();
    for (name, entry) in dto.files {
        let unit = SizeUnit::from_str(entry.unit.as_str()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown size unit: {}", entry.unit))
        })?;

        files.insert(
            name,
            DirectoryEntry {
                size: entry.size,
                unit,
                owner: entry.owner,
                mode: entry.mode,
                modified: entry.modified,
            },
        );
    }

    let length = if dto.length == files.len() { dto.length } else { files.len() };

    Ok(ParentDirectory { length, files })
}

pub fn file_pdir_upload(path: &str, file_base64: &str) -> Result<(), String> {
    let full_path = normalize_absolute_path(path)?;
    let decoded = general_purpose::STANDARD
        .decode(file_base64)
        .map_err(|e| format!("file_pdir_upload base64 decode error: {}", e))?;
    let reencoded = general_purpose::STANDARD.encode(decoded);

    let parent = Path::new(&full_path).parent().map(|p| p.to_path_buf());
    let mut script = String::new();
    if let Some(parent_path) = parent {
        if !parent_path.as_os_str().is_empty() {
            script.push_str(&format!(
                "mkdir -p {}\n",
                shell_quote(parent_path.to_string_lossy().as_ref())
            ));
        }
    }
    script.push_str("TMP_FILE=$(mktemp)\n");
    script.push_str("cleanup() { rm -f \"$TMP_FILE\"; }\n");
    script.push_str("trap cleanup EXIT\n");
    script.push_str("cat <<'EOF' | base64 -d >\"$TMP_FILE\"\n");
    script.push_str(&reencoded);
    script.push_str("\nEOF\n");
    script.push_str("chmod 0644 \"$TMP_FILE\"\n");
    script.push_str(&format!("mv \"$TMP_FILE\" {}\n", shell_quote(&full_path)));

    let result =
        execute_host_body(&script).map_err(|e| format!("file_pdir_upload host error: {}", e))?;
    if result.status != 0 {
        let message = if result.output.trim().is_empty() {
            format!("upload failed with status {}", result.status)
        } else {
            result.output.trim().to_string()
        };
        return Err(message);
    }

    Ok(())
}

pub fn file_pdir_download(path: &str, filename: &str) -> Result<String, String> {
    let full_path = join_path_filename(path, filename)?;
    let command = format!(
        "if [ ! -f {} ]; then printf 'NOTFOUND\\n'; exit 1; fi\nbase64 {} | tr -d '\n'\n",
        shell_quote(&full_path),
        shell_quote(&full_path)
    );

    let result =
        execute_host_body(&command).map_err(|e| format!("file_pdir_download host error: {}", e))?;

    if result.status != 0 {
        if result.output.trim() == "NOTFOUND" {
            return Err("file not found".to_string());
        }
        let message = if result.output.trim().is_empty() {
            format!("download failed with status {}", result.status)
        } else {
            result.output.trim().to_string()
        };
        return Err(message);
    }

    let data = result.output.replace(['\n', '\r'], "");
    Ok(data)
}

fn normalize_absolute_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("path cannot be empty".to_string());
    }
    if !trimmed.starts_with('/') {
        return Err("path must be absolute".to_string());
    }
    if trimmed.contains("..") {
        return Err("path cannot contain '..'".to_string());
    }
    Ok(trimmed.to_string())
}

fn join_path_filename(path: &str, filename: &str) -> Result<String, String> {
    let base = normalize_absolute_path(path)?;
    if filename.is_empty() {
        return Err("filename cannot be empty".to_string());
    }
    if filename.contains('/') || filename.contains("..") {
        return Err("filename contains invalid characters".to_string());
    }
    let mut full = PathBuf::from(base);
    full.push(filename);
    Ok(full.to_string_lossy().to_string())
}
