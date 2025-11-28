use crate::{
    commons::{ResponseResult, ResponseType},
    handles::chm::mca::types::{get_revokeds, get_valids, RevokeRequest},
    AppState, RestfulResult,
};
use actix_web::{get, post, web, Scope};
use chm_grpc::{
    restful::{GetValidCertsRequest, RevokeCertRequest},
    tonic,
};
use utoipa::OpenApi;

mod translate;
pub mod types;

/// URL: /api/chm/mCA
pub fn mca_scope() -> Scope {
    web::scope("/mCA").service(valid).service(revoked).service(revoke)
}

#[derive(OpenApi)]
#[openapi(
    paths(valid, revoked, revoke),
    tags(
        (name = "Mca", description = "CHM 憑證相關 API")
    )
)]
pub struct McaApi;

#[utoipa::path(
    get,
    path = "/api/chm/mCA/valid",
    tag = "Mca",
    responses(
        (status = 200, description = "取得有效憑證列表", body = get_valids),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("/valid")]
async fn valid(app_state: web::Data<AppState>) -> RestfulResult<web::Json<get_valids>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_valid_certs(GetValidCertsRequest {})
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    Ok(web::Json(resp.into()))
}

#[utoipa::path(
    get,
    path = "/api/chm/mCA/revoked",
    tag = "Mca",
    responses(
        (status = 200, description = "取得吊銷憑證列表", body = get_revokeds),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("/revoked")]
async fn revoked(app_state: web::Data<AppState>) -> RestfulResult<web::Json<get_revokeds>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_revoked_certs(chm_grpc::restful::GetRevokedCertsRequest {})
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    Ok(web::Json(resp.into()))
}

#[utoipa::path(
    post,
    path = "/api/chm/mCA/revoke",
    tag = "Mca",
    request_body = RevokeRequest,
    responses(
        (status = 200, description = "憑證吊銷成功", body = ResponseResult,example = json!({
                "Type": "Ok",
                "Message": "Certificate revoked successfully"
            })),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("/revoke")]
async fn revoke(
    app_state: web::Data<AppState>,
    data: web::Json<RevokeRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = data.into_inner();
    let mut client = app_state.gclient.clone();
    let resp = client.revoke_cert(RevokeCertRequest { name: data.name, reason: data.reason }).await;

    match resp {
        Ok(ok_resp) => {
            let inner = ok_resp.into_inner();
            let r: ResponseResult = inner.into();
            Ok(web::Json(r))
        }
        Err(status) => {
            let message = match status.code() {
                tonic::Code::Cancelled | tonic::Code::Unavailable => {
                    format!("gRPC 連線中斷: {status}")
                }
                _ => format!("gRPC 執行失敗: {status}"),
            };
            let r = ResponseResult { r#type: ResponseType::Err, message };
            Ok(web::Json(r))
        }
    }
}
