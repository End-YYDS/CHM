use std::collections::HashMap;

use chm_grpc::restful;

use crate::{
    commons::translate::AppError,
    handles::software::{
        types::{
            ActionResponse, GetSoftwareResponse, PackageActionResult, PackageInfo, PackageStatus,
            PcPackages,
        },
        PackageActionKind,
    },
};
impl From<restful::GetSoftwareResponse> for GetSoftwareResponse {
    fn from(src: restful::GetSoftwareResponse) -> Self {
        let pcs = src.pcs.into_iter().map(|(uuid, pkgs)| (uuid, pkgs.into())).collect();
        Self { pcs }
    }
}

impl From<restful::PcPackages> for PcPackages {
    fn from(src: restful::PcPackages) -> Self {
        let packages = src.packages.into_iter().map(|(name, info)| (name, info.into())).collect();
        Self { packages }
    }
}

impl From<restful::PackageInfo> for PackageInfo {
    fn from(src: restful::PackageInfo) -> Self {
        Self { version: src.version, status: map_status(src.status) }
    }
}

pub trait ActionResponseExt {
    #[allow(clippy::result_large_err)]
    fn try_into_action_response(self, kind: PackageActionKind) -> Result<ActionResponse, AppError>;
}

impl ActionResponseExt for restful::PackageActionResponse {
    fn try_into_action_response(self, kind: PackageActionKind) -> Result<ActionResponse, AppError> {
        let length = usize::try_from(self.length)?;
        let packages = self
            .packages
            .into_iter()
            .map(|(pkg, result)| (pkg, convert_action_result(result, &kind)))
            .collect::<HashMap<_, _>>();
        Ok(ActionResponse { packages, length })
    }
}

fn convert_action_result(
    src: restful::PackageActionResult,
    kind: &PackageActionKind,
) -> PackageActionResult {
    match kind {
        PackageActionKind::Install => {
            PackageActionResult { installed: src.installed, notinstalled: src.notinstalled }
        }
        PackageActionKind::Delete => {
            PackageActionResult { installed: src.installed, notinstalled: src.notinstalled }
        }
    }
}

fn map_status(status: i32) -> PackageStatus {
    match restful::PackageStatus::try_from(status).unwrap_or(restful::PackageStatus::Unspecified) {
        restful::PackageStatus::Installed => PackageStatus::Installed,
        restful::PackageStatus::Notinstall => PackageStatus::Notinstall,
        restful::PackageStatus::Unspecified => PackageStatus::Notinstall,
    }
}
