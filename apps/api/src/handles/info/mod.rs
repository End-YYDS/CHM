mod types;

use actix_web::{get, post, web, HttpResponse, Scope};
use std::collections::HashMap;
use types::*;

pub fn info_scope() -> Scope {
    web::scope("/info").service(_get_info_all).service(_post_info_get)
}

/// GET /api/info/getAll
#[get("/getAll")]
async fn _get_info_all() -> HttpResponse {
    // TODO: 以你的監控來源取值
    let info = InfoCounts { safe: 8, warn: 2, dang: 1 };
    let cluster = ClusterSummary { cpu: 37.5, memory: 62.0, disk: 48.3 };
    HttpResponse::Ok().json(GetAllInfoResponse { info, cluster })
}

/// POST /api/info/get
#[post("/get")]
async fn _post_info_get(data: web::Json<InfoGetRequest>) -> web::Json<InfoGetResponse> {
    dbg!(&data);
    // 假資料（uuid -> metrics）；實作時依 zone/target/uuid 過濾與聚合
    let all: [(&str, PcMetrics); 3] = [
        ("uuid-a", PcMetrics { cpu: 10.0, memory: 20.0, disk: 30.0 }),
        ("uuid-b", PcMetrics { cpu: 40.0, memory: 50.0, disk: 60.0 }),
        ("uuid-c", PcMetrics { cpu: 70.0, memory: 80.0, disk: 90.0 }),
    ];

    let mut pcs: HashMap<String, PcMetrics> = HashMap::new();

    match &data.uuid {
        None => {
            // 取全部
            for (k, v) in all {
                pcs.insert(k.to_string(), v);
            }
        }
        Some(u) => {
            if let Some((k, v)) = all.iter().find(|(id, _)| *id == u) {
                pcs.insert((*k).to_string(), *v);
            }
        }
    }

    // 這裡示範直接回傳 Cpu/Memory/Disk 全部三欄；若要依 Target
    // 精簡欄位，能改為自訂序列化或分歧型別
    let length = pcs.len();
    web::Json(InfoGetResponse { pcs, length })
}
