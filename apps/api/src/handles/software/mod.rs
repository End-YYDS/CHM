mod types;

use crate::{AppState, RestfulResult, commons::translate::AppError};
use actix_web::{Scope, delete, get, post, web};
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
    let req = GrpcInstallSoftwareRequest { uuids: data.uuids, packages: data.packages };
    let resp = client
        .install_software(req)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .try_into()
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
    let req = GrpcDeleteSoftwareRequest { uuids: data.uuids, packages: data.packages };
    let resp = client
        .delete_software(req)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .try_into()
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

impl From<restful::PackageActionResult> for PackageActionResult {
    fn from(src: restful::PackageActionResult) -> Self {
        Self { installed: src.installed, notinstalled: src.notinstalled }
    }
}

impl TryFrom<restful::PackageActionResponse> for ActionResponse {
    type Error = AppError;

    fn try_from(src: restful::PackageActionResponse) -> Result<Self, Self::Error> {
        let length = usize::try_from(src.length)?;
        let packages = src
            .packages
            .into_iter()
            .map(|(pkg, result)| (pkg, result.into()))
            .collect::<HashMap<String, PackageActionResult>>();
        Ok(Self { packages, length })
    }
}

fn map_status(status: i32) -> PackageStatus {
    match restful::PackageStatus::try_from(status).unwrap_or(restful::PackageStatus::Unspecified) {
        restful::PackageStatus::Installed => PackageStatus::Installed,
        restful::PackageStatus::Notinstall => PackageStatus::Notinstall,
        restful::PackageStatus::Unspecified => PackageStatus::Notinstall,
    }
}
