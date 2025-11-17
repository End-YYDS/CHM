// Functions: get_software, software_install, software_delete

use std::{
    collections::{BTreeMap, HashSet},
    io,
};

use crate::{
    execute_host_body, family_key, join_shell_args, last_non_empty_line, make_sysinfo_command,
    send_to_hostd, shell_quote, ReturnInfo, SystemInfo,
};
use serde::Deserialize;
use serde_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageStatus {
    Installed,
    Notinstall,
}

impl PackageStatus {
    fn from_str(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "installed" => Some(PackageStatus::Installed),
            "notinstall" => Some(PackageStatus::Notinstall),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct SoftwarePackage {
    pub version: String,
    pub status:  PackageStatus,
}

#[derive(Debug)]
pub struct SoftwareInventory {
    pub packages: BTreeMap<String, SoftwarePackage>,
}

#[derive(Debug, Clone, Copy)]
enum PackageManagerKind {
    Debian,
    Redhat,
}

#[derive(Debug, Clone, Copy)]
enum PackageAction {
    Install,
    Remove,
}

impl PackageAction {
    fn display_name(&self) -> &'static str {
        match self {
            PackageAction::Install => "software_install",
            PackageAction::Remove => "software_delete",
        }
    }

    fn rpm_subcommand(&self) -> &'static str {
        match self {
            PackageAction::Install => "install",
            PackageAction::Remove => "remove",
        }
    }
}

#[derive(Deserialize)]
struct SoftwareInventoryDto {
    #[serde(rename = "Packages")]
    packages: BTreeMap<String, SoftwarePackageDto>,
}

#[derive(Deserialize)]
struct SoftwarePackageDto {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Status")]
    status:  String,
}

#[derive(Deserialize)]
struct SoftwareInstallArg {
    #[serde(rename = "Packages")]
    packages: Vec<String>,
}

#[derive(Deserialize)]
struct SoftwareDeleteArg {
    #[serde(rename = "Package", alias = "Packages")]
    packages: Vec<String>,
}

pub fn software_info_structured(_sys: &SystemInfo) -> io::Result<SoftwareInventory> {
    let cmd = make_sysinfo_command("software_status");
    let output = send_to_hostd(&cmd)?;

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::other(info.message));
    }

    let dto: SoftwareInventoryDto = serde_json::from_str(&output).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse software inventory JSON: {}", e),
        )
    })?;

    convert_software_inventory(dto)
}

pub fn execute_software_delete(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    run_software_action(PackageAction::Remove, argument, sys)
}

pub fn execute_software_install(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    run_software_action(PackageAction::Install, argument, sys)
}

fn convert_software_inventory(dto: SoftwareInventoryDto) -> io::Result<SoftwareInventory> {
    let mut packages = BTreeMap::new();
    for (name, pkg) in dto.packages {
        let status = PackageStatus::from_str(&pkg.status).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown package status: {}", pkg.status),
            )
        })?;

        packages.insert(name, SoftwarePackage { version: pkg.version, status });
    }

    Ok(SoftwareInventory { packages })
}

fn run_software_action(
    action: PackageAction,
    argument: &str,
    sys: &SystemInfo,
) -> Result<String, String> {
    let packages = match action {
        PackageAction::Install => parse_package_list(argument, action, |payload| {
            serde_json::from_str::<SoftwareInstallArg>(payload)
                .map(|arg| arg.packages)
                .map_err(|e| format!("software_install payload parse error: {}", e))
        })?,
        PackageAction::Remove => parse_package_list(argument, action, |payload| {
            serde_json::from_str::<SoftwareDeleteArg>(payload)
                .map(|arg| arg.packages)
                .map_err(|e| format!("software_delete payload parse error: {}", e))
        })?,
    };

    let manager = detect_package_manager(sys)?;
    let command = build_package_command(action, &packages, manager);
    let success_message = format!("{}: {}", action.display_name(), packages.join(", "));
    let body = format!("{}\nprintf '%s\\n' {}\n", command, shell_quote(&success_message));

    let result = execute_host_body(&body)?;
    let command_output = result.output.clone();
    if result.status == 0 {
        if let Err(verification_error) = verify_package_state(action, &packages, manager) {
            let mut message = verification_error;
            if !command_output.trim().is_empty() {
                message = format!("{}\nInstaller output:\n{}", message, command_output.trim());
            }
            return Err(message);
        }
        let message = last_non_empty_line(&result.output)
            .map(|line| line.to_string())
            .unwrap_or_else(|| success_message.clone());
        Ok(message)
    } else if result.output.trim().is_empty() {
        Err(format!("{} failed with status {}", success_message, result.status))
    } else {
        Err(result.output.trim().to_string())
    }
}

fn parse_package_list<F>(
    argument: &str,
    action: PackageAction,
    parser: F,
) -> Result<Vec<String>, String>
where
    F: Fn(&str) -> Result<Vec<String>, String>,
{
    let raw_packages = parser(argument)?;
    let mut unique = HashSet::new();
    let mut packages = Vec::new();

    for pkg in raw_packages {
        let trimmed = pkg.trim();
        if trimmed.is_empty() {
            continue;
        }
        validate_package_name(trimmed)?;
        if unique.insert(trimmed.to_string()) {
            packages.push(trimmed.to_string());
        }
    }

    if packages.is_empty() {
        return Err(format!("{} requires at least one package", action.display_name()));
    }

    Ok(packages)
}

fn validate_package_name(name: &str) -> Result<(), String> {
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '.' | ':'))
    {
        return Err(format!("package name contains unsupported characters: {}", name));
    }
    Ok(())
}

fn build_package_command(
    action: PackageAction,
    packages: &[String],
    manager: PackageManagerKind,
) -> String {
    let quoted = join_shell_args(packages);

    match manager {
        PackageManagerKind::Debian => match action {
            PackageAction::Install => format!(
                "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive \
                 apt-get install -y {}",
                quoted
            ),
            PackageAction::Remove => {
                format!("DEBIAN_FRONTEND=noninteractive apt-get purge -y {}", quoted)
            }
        },
        PackageManagerKind::Redhat => {
            let sub = action.rpm_subcommand();
            format!(
                "if command -v dnf >/dev/null 2>&1; then dnf -y {} {}; else yum -y {} {}; fi",
                sub, quoted, sub, quoted
            )
        }
    }
}

fn detect_package_manager(sys: &SystemInfo) -> Result<PackageManagerKind, String> {
    let os = sys.os_id.as_str();
    if matches!(
        os,
        "ubuntu" | "debian" | "linuxmint" | "elementary" | "pop" | "zorin" | "kali" | "raspbian"
    ) {
        return Ok(PackageManagerKind::Debian);
    }

    if matches!(
        os,
        "centos" | "rhel" | "rocky" | "almalinux" | "scientific" | "oracle" | "fedora" | "amazon"
    ) {
        return Ok(PackageManagerKind::Redhat);
    }

    match family_key(sys) {
        "debian_like" => Ok(PackageManagerKind::Debian),
        "redhat_like" => Ok(PackageManagerKind::Redhat),
        _ => Err(format!("unsupported package manager for {} {}", sys.os_id, sys.version_id)),
    }
}

fn verify_package_state(
    action: PackageAction,
    packages: &[String],
    manager: PackageManagerKind,
) -> Result<(), String> {
    let script = build_verification_script(action, packages, manager);
    let result = execute_host_body(&script)?;

    if result.status != 0 {
        let output = result.output.trim();
        if output.is_empty() {
            return Err("package verification script failed with unknown error".to_string());
        }
        return Err(format!("package verification script failed: {}", output));
    }

    let mut issues = Vec::new();
    for line in result.output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((name, status)) = trimmed.split_once('|') {
            issues.push(format!("{} (status: {})", name, status));
        } else {
            issues.push(trimmed.to_string());
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        let joined = issues.join(", ");
        let hint = match action {
            PackageAction::Install => {
                "Packages did not appear after installation. Possible causes: insufficient \
                 privileges, read-only filesystem, or missing repositories."
            }
            PackageAction::Remove => {
                "Packages still appear after deletion. Possible causes: insufficient privileges, \
                 package dependencies, or read-only filesystem."
            }
        };
        Err(format!("{} verification failed: {}. {}", action.display_name(), joined, hint))
    }
}

fn build_verification_script(
    action: PackageAction,
    packages: &[String],
    manager: PackageManagerKind,
) -> String {
    let package_list = packages.iter().map(|pkg| shell_quote(pkg)).collect::<Vec<_>>().join(" ");

    match manager {
        PackageManagerKind::Debian => match action {
            PackageAction::Install => format!(
                "set +e\nfor pkg in {packages}; do\n  status=$(dpkg-query -W -f='${{Status}}' \
                 \"$pkg\" 2>/dev/null)\n  if printf '%s' \"$status\" | grep -q 'install ok \
                 installed'; then\n    :\n  else\n    if [ -z \"$status\" ]; then\n      \
                 status='not-installed'\n    fi\n    printf '%s|%s\\n' \"$pkg\" \"$status\"\n  \
                 fi\ndone\nexit 0\n",
                packages = package_list
            ),
            PackageAction::Remove => format!(
                "set +e\nfor pkg in {packages}; do\n  status=$(dpkg-query -W -f='${{Status}}' \
                 \"$pkg\" 2>/dev/null)\n  if printf '%s' \"$status\" | grep -q 'install ok \
                 installed'; then\n    printf '%s|still-installed\\n' \"$pkg\"\n  fi\ndone\nexit \
                 0\n",
                packages = package_list
            ),
        },
        PackageManagerKind::Redhat => match action {
            PackageAction::Install => format!(
                "set +e\nfor pkg in {packages}; do\n  if rpm -q \"$pkg\" >/dev/null 2>&1; \
                     then\n    :\n  else\n    printf '%s|not-installed\\n' \"$pkg\"\n  \
                     fi\ndone\nexit 0\n",
                packages = package_list
            ),
            PackageAction::Remove => format!(
                "set +e\nfor pkg in {packages}; do\n  if rpm -q \"$pkg\" >/dev/null 2>&1; \
                     then\n    printf '%s|still-installed\\n' \"$pkg\"\n  fi\ndone\nexit 0\n",
                packages = package_list
            ),
        },
    }
}
