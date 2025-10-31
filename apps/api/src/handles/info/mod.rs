mod types;

use actix_web::{get, post, web, Scope};
// use std::collections::HashMap;
use crate::{
    // commons::{ResponseResult, ResponseType},
    AppState,
};
use chm_grpc::{
    restful::{GetAllInfoRequest as Grpc_GetAllInfoRequest, GetInfoRequest as Grpc_GetInfoRequest},
    tonic,
};
use types::*;

pub fn info_scope() -> Scope {
    web::scope("/info").service(_get_info_all).service(_post_info_get)
}
// GET /api/info/getAll
// #[get("/getAll")]
// async fn _get_info_all() -> HttpResponse {
//     let info = InfoCounts { safe: 8, warn: 2, dang: 1 };
//     let cluster = ClusterSummary { cpu: 37.5, memory: 62.0, disk: 48.3 };
//     HttpResponse::Ok().json(GetAllInfoResponse { info, cluster })
// }

/// GET /api/info/getAll
#[get("/getAll")]
async fn _get_info_all(
    app_state: web::Data<AppState>,
) -> actix_web::Result<web::Json<GetAllInfoResponse>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_all_info(Grpc_GetAllInfoRequest {})
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner();
    let info = resp.info.expect("gRPC info missing");
    let info = InfoCounts { safe: info.safe, warn: info.warn, dang: info.dang };
    let cluster = resp.cluster.expect("gRPC cluster missing");
    let cluster =
        ClusterSummary { cpu: cluster.cpu, memory: cluster.memory, disk: cluster.disk };
    let result = GetAllInfoResponse { info, cluster };
    Ok(web::Json(result))
}

/// POST /api/info/get
// #[post("/get")]
// async fn _post_info_get(data: web::Json<InfoGetRequest>) -> web::Json<InfoGetResponse> {
//     dbg!(&data);
//     // 假資料（uuid -> metrics）；實作時依 zone/target/uuid 過濾與聚合
//     let all: [(&str, PcMetrics); 3] = [
//         ("uuid-a", PcMetrics { cpu: 10.0, memory: 20.0, disk: 30.0 }),
//         ("uuid-b", PcMetrics { cpu: 40.0, memory: 50.0, disk: 60.0 }),
//         ("uuid-c", PcMetrics { cpu: 70.0, memory: 80.0, disk: 90.0 }),
//     ];

//     let mut pcs: HashMap<String, PcMetrics> = HashMap::new();

//     match &data.uuid {
//         None => {
//             // 取全部
//             for (k, v) in all {
//                 pcs.insert(k.to_string(), v);
//             }
//         }
//         Some(u) => {
//             if let Some((k, v)) = all.iter().find(|(id, _)| *id == u) {
//                 pcs.insert((*k).to_string(), *v);
//             }
//         }
//     }

//     // 這裡示範直接回傳 Cpu/Memory/Disk 全部三欄；若要依 Target
//     // 精簡欄位，能改為自訂序列化或分歧型別
//     let length = pcs.len();
//     web::Json(InfoGetResponse { pcs, length })
// }

// POST /api/info/get
#[post("/get")]
async fn _post_info_get(
    app_state: web::Data<AppState>,
    payload: web::Json<InfoGetRequest>,
) -> actix_web::Result<web::Json<InfoGetResponse>> {
    use std::collections::HashMap;
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    let grpc_req = Grpc_GetInfoRequest {
        zone:   data.zone as i32,
        target: data.target as i32,
        uuid:   data.uuid.clone(),
    };
    let resp = client
        .get_info(grpc_req)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner();
    let mut pcs: HashMap<String, PcMetrics> = resp
        .pcs
        .into_iter()
        .map(|(k, v)| (k, PcMetrics { cpu: v.cpu, memory: v.memory, disk: v.disk }))
        .collect();
    if let Some(uuid) = data.uuid {
        pcs.retain(|k, _| k == &uuid);
    }
    let mut safe: HashMap<String, PcMetrics> = HashMap::new();
    let mut warn: HashMap<String, PcMetrics> = HashMap::new();
    let mut dang: HashMap<String, PcMetrics> = HashMap::new();
    for (uuid, metrics) in &pcs {
        if metrics.cpu < 50.0 && metrics.memory < 60.0 && metrics.disk < 70.0 {
            safe.insert(uuid.clone(), *metrics);
        } else if metrics.cpu < 80.0 && metrics.memory < 85.0 && metrics.disk < 90.0 {
            warn.insert(uuid.clone(), *metrics);
        } else {
            dang.insert(uuid.clone(), *metrics);
        }
    }
    let zone = data.zone;
    let target = data.target;
    let filtered_pcs = match zone {
        Zone::info => match target {
            Target::Safe => safe,
            Target::Warn => warn,
            Target::Dang => dang,
            _ => pcs,
        },
        Zone::cluster => pcs.clone(),
    };
    let length = filtered_pcs.len();
    let result = InfoGetResponse { pcs: filtered_pcs, length };
    Ok(web::Json(result))
}
