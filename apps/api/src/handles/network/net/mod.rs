mod types;

use actix_web::{delete, get, patch, post, put, web, HttpResponse, Scope};
use std::collections::HashMap;

use crate::commons::{ResponseResult, ResponseType};
use types::*;

pub fn net_scope() -> Scope {
    web::scope("/net")
        .service(_get_net_all)
        .service(_post_net_root)
        .service(_delete_net_root)
        .service(_patch_net_root)
        .service(_put_net_root)
        .service(_post_net_action_up)
        .service(_post_net_action_down)
}

/// GET /api/network/net
#[get("")]
async fn _get_net_all() -> HttpResponse {
    // demo data
    let mut nets = HashMap::new();
    nets.insert(
        "eth0".into(),
        NetworkItem {
            nic_type:  NicType::Physical,
            ipv4:      "192.168.1.10".into(),
            netmask:   "255.255.255.0".into(),
            mac:       "aa:bb:cc:dd:ee:ff".into(),
            broadcast: "192.168.1.255".into(),
            mtu:       1500,
            status:    NicStatus::Up,
        },
    );
    let pc_networks = PcNetworks { length: nets.len(), networks: nets };

    let mut pcs = HashMap::new();
    pcs.insert("uuid-a".into(), pc_networks);

    HttpResponse::Ok().json(GetAllNetResponse { length: pcs.len(), pcs })
}

/// POST /api/network/net
#[post("")]
async fn _post_net_root(data: web::Json<CreateNetRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Network added".into() })
}

/// DELETE /api/network/net
#[delete("")]
async fn _delete_net_root(data: web::Json<DeleteNetRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Network deleted".into() })
}

/// PATCH /api/network/net
#[patch("")]
async fn _patch_net_root(data: web::Json<PatchNetRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    // 實作時可檢查 data.field 與對應的 Option 是否存在
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Network updated (partial)".into(),
    })
}

/// PUT /api/network/net
#[put("")]
async fn _put_net_root(data: web::Json<PutNetRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Network replaced".into() })
}

/// POST /api/network/net/action/up
#[post("/action/up")]
async fn _post_net_action_up(data: web::Json<ActionNetRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Interface up".into() })
}

/// POST /api/network/net/action/down
#[post("/action/down")]
async fn _post_net_action_down(data: web::Json<ActionNetRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Interface down".into() })
}
