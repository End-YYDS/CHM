mod types;

use actix_web::{get, patch, put, web, HttpResponse, Scope};
use std::collections::HashMap;

use crate::commons::{ResponseResult, ResponseType};
use types::*;

pub fn dns_scope() -> Scope {
    web::scope("/dns").service(_get_dns_all).service(_patch_dns_hostname).service(_put_dns_servers)
}

/// GET /api/network/dns
#[get("")]
async fn _get_dns_all() -> HttpResponse {
    let mut pcs = HashMap::new();
    pcs.insert(
        "uuid-a".into(),
        PcDns {
            hostname: "node-a".into(),
            dns:      DnsPair { primary: "8.8.8.8".into(), secondary: "1.1.1.1".into() },
        },
    );
    pcs.insert(
        "uuid-b".into(),
        PcDns {
            hostname: "node-b".into(),
            dns:      DnsPair { primary: "8.8.4.4".into(), secondary: "9.9.9.9".into() },
        },
    );
    HttpResponse::Ok().json(GetAllDnsResponse { pcs })
}

/// PATCH /api/network/dns  （更改 Hostname）
#[patch("")]
async fn _patch_dns_hostname(data: web::Json<PatchHostnameRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    // 實作：切換指定 UUID 的 hostname
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Hostname updated".into() })
}

/// PUT /api/network/dns  （更改 DNS Server IPs）
#[put("")]
async fn _put_dns_servers(data: web::Json<PutDnsRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    // 實作：若只改 Primary，Secondary 沿用舊值（可在此做取舊值補全）
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "DNS servers updated".into() })
}
