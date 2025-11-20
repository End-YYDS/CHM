mod types;

use crate::{commons::translate::AppError, AppState, RestfulResult};
use actix_web::{delete, get, post, web, Scope};
use chm_grpc::restful::{
    self, DeleteSoftwareRequest as GrpcDeleteSoftwareRequest,
    GetSoftwareRequest as GrpcGetSoftwareRequest,
    InstallSoftwareRequest as GrpcInstallSoftwareRequest,
};
use std::collections::HashMap;

use types::*;

pub fn software_scope() -> Scope {
    web::scope("/software").service(_get_software).service(_post_software).service(_delete_software)
}

/// GET /api/software
#[get("")]
async fn _get_software(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<GetSoftwareResponse>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_software(GrpcGetSoftwareRequest {})
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

/// POST /api/software
#[post("")]
async fn _post_software(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<InstallRequest>,
) -> RestfulResult<web::Json<ActionResponse>> {
    let mut client = app_state.gclient.clone();
    let req = GrpcInstallSoftwareRequest {
        uuids:    data.uuids,
        packages: data.packages.unwrap_or_default(),
    };
    let resp = client
        .install_software(req)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .try_into_action_response(PackageActionKind::Install)
        .inspect_err(|e: &AppError| tracing::error!(?e))?;
    Ok(web::Json(resp))
}

/// DELETE /api/software
#[delete("")]
async fn _delete_software(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<DeleteRequest>,
) -> RestfulResult<web::Json<ActionResponse>> {
    let mut client = app_state.gclient.clone();
    let req = GrpcDeleteSoftwareRequest {
        uuids:    data.uuids,
        packages: data.packages.unwrap_or_default(),
    };
    let resp = client
        .delete_software(req)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .try_into_action_response(PackageActionKind::Delete)
        .inspect_err(|e: &AppError| tracing::error!(?e))?;
    Ok(web::Json(resp))
}

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

enum PackageActionKind {
    Install,
    Delete,
}

trait ActionResponseExt {
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
