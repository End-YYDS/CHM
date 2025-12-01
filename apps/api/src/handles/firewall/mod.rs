pub mod types;

use actix_web::{delete, get, post, put, web, HttpResponse, Scope};
use std::collections::HashMap;
use types::*;

use crate::commons::{ResponseResult, ResponseType};

pub fn firewall_scope() -> Scope {
    web::scope("/firewall")
        .service(_get_firewall_pcs)
        .service(_get_firewall_status)
        .service(_post_firewall_rule)
        .service(_delete_firewall_rule)
        .service(_put_firewall_status)
        .service(_put_firewall_policy)
}

/// GET /api/firewall/pcs
#[get("/pcs")]
async fn _get_firewall_pcs() -> HttpResponse {
    let mut pcs: HashMap<String, String> = HashMap::new();
    pcs.insert("uuid-1".into(), "host-a".into());
    pcs.insert("uuid-2".into(), "host-b".into());
    HttpResponse::Ok().json(serde_json::json!({
        "Pcs": pcs,
        "Length": 2
    }))
}

#[get("")]
async fn _get_firewall_status(query: web::Query<FirewallRequest>) -> HttpResponse {
    dbg!(&query);
    let rules = vec![Rule {
        target:      Target::Drop,
        protocol:    "tcp".into(),
        in_if:       "eth0".into(),
        out_if:      "*".into(),
        source:      "192.168.1.100".into(),
        destination: "0.0.0.0/0".into(),
        options:     "tcp dpt:22".into(),
    }];
    let chain =
        Chain { name: "INPUT".into(), policy: Target::Accept, rules_length: rules.len(), rules };
    HttpResponse::Ok()
        .json(FirewallStatusResponse { status: FirewallStatus::Active, chains: vec![chain] })
}

#[post("/rule")]
async fn _post_firewall_rule(data: web::Json<AddRuleRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Rule added".into() })
}

#[delete("/rule")]
async fn _delete_firewall_rule(data: web::Json<DeleteRuleRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Rule deleted".into() })
}

#[put("/status")]
async fn _put_firewall_status(data: web::Json<PutStatusRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Status updated".into() })
}

#[put("/policy")]
async fn _put_firewall_policy(data: web::Json<PutPolicyRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Policy updated".into() })
}
