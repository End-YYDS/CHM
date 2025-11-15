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

mod translate;
pub mod types;

pub fn mca_scope() -> Scope {
    web::scope("/mCA").service(valid).service(revoked).service(revoke)
}

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
