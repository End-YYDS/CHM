pub mod types;

use actix_web::{delete, get, post, put, web, HttpResponse, Scope};
use chm_grpc::{
    common::{self, action_result},
    restful::{
        self, restful_service_client::RestfulServiceClient, ChainKind,
        FirewallStatus as GrpcFirewallStatus, Verdict,
    },
};
use chm_project_const::uuid::Uuid;
use types::{FirewallStatus as ApiFirewallStatus, *};

use crate::{
    commons::{ResponseResult, ResponseType, UuidRequest},
    AppState,
};

pub fn firewall_scope() -> Scope {
    web::scope("/firewall")
        .service(get_firewall_pcs)
        .service(get_firewall_status)
        .service(post_firewall_rule)
        .service(delete_firewall_rule)
        .service(put_firewall_status)
        .service(put_firewall_policy)
}

/// GET /api/firewall/pcs
#[get("/pcs")]
async fn get_firewall_pcs(state: web::Data<AppState>) -> HttpResponse {
    let mut client: RestfulServiceClient<_> = state.gclient.clone();
    match client.get_firewall_pcs(restful::GetFirewallPcsRequest {}).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            HttpResponse::Ok().json(serde_json::json!({
                "Pcs": inner.pcs,
                "Length": inner.length
            }))
        }
        Err(err) => HttpResponse::InternalServerError().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: format!("取得防火牆主機列表失敗: {err}"),
        }),
    }
}

#[get("")]
async fn get_firewall_status(
    query: web::Query<UuidRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    if Uuid::parse_str(&query.uuid).is_err() {
        return HttpResponse::BadRequest().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "Uuid 格式不正確".into(),
        });
    }

    let mut client: RestfulServiceClient<_> = state.gclient.clone();
    match client.get_firewall(restful::GetFirewallRequest { uuid: query.uuid.clone() }).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            match convert_firewall_status(inner) {
                Ok(status) => HttpResponse::Ok().json(status),
                Err(msg) => HttpResponse::InternalServerError()
                    .json(ResponseResult { r#type: ResponseType::Err, message: msg }),
            }
        }
        Err(err) => HttpResponse::InternalServerError().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: format!("取得防火牆狀態失敗: {err}"),
        }),
    }
}

#[post("/rule")]
async fn post_firewall_rule(
    data: web::Json<AddRuleRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let chain = match parse_chain(&data.chain) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    let target = match parse_verdict(&data.target) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    let req = restful::AddFirewallRuleRequest {
        uuid: data.uuid.clone(),
        chain,
        target,
        protocol: data.protocol.clone(),
        in_if: data.in_if.clone(),
        out_if: data.out_if.clone(),
        source: data.source.clone(),
        destination: data.destination.clone(),
        options: data.options.clone(),
    };

    let mut client: RestfulServiceClient<_> = state.gclient.clone();
    match client.add_firewall_rule(req).await {
        Ok(resp) => HttpResponse::Ok().json(to_response_result(resp.into_inner().result)),
        Err(err) => HttpResponse::InternalServerError().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: format!("新增規則失敗: {err}"),
        }),
    }
}

#[delete("/rule")]
async fn delete_firewall_rule(
    data: web::Json<DeleteRuleRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let chain = match parse_chain(&data.chain) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    if data.rule_id <= 0 {
        return HttpResponse::BadRequest().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "RuleId 必須大於 0".into(),
        });
    }

    let req = restful::DeleteFirewallRuleRequest {
        uuid: data.uuid.clone(),
        chain,
        rule_id: data.rule_id as u64,
    };

    let mut client: RestfulServiceClient<_> = state.gclient.clone();
    match client.delete_firewall_rule(req).await {
        Ok(resp) => HttpResponse::Ok().json(to_response_result(resp.into_inner().result)),
        Err(err) => HttpResponse::InternalServerError().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: format!("刪除規則失敗: {err}"),
        }),
    }
}

#[put("/status")]
async fn put_firewall_status(
    data: web::Json<PutStatusRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let status = match parse_status(&data.status) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    let req = restful::PutFirewallStatusRequest { uuid: data.uuid.clone(), status };

    let mut client: RestfulServiceClient<_> = state.gclient.clone();
    match client.put_firewall_status(req).await {
        Ok(resp) => HttpResponse::Ok().json(to_response_result(resp.into_inner().result)),
        Err(err) => HttpResponse::InternalServerError().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: format!("更新防火牆狀態失敗: {err}"),
        }),
    }
}

#[put("/policy")]
async fn put_firewall_policy(
    data: web::Json<PutPolicyRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let chain = match parse_chain(&data.chain) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    let policy = match parse_verdict(&data.policy) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    let req = restful::PutFirewallPolicyRequest { uuid: data.uuid.clone(), chain, policy };
    let mut client: RestfulServiceClient<_> = state.gclient.clone();
    match client.put_firewall_policy(req).await {
        Ok(resp) => HttpResponse::Ok().json(to_response_result(resp.into_inner().result)),
        Err(err) => HttpResponse::InternalServerError().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: format!("更新預設策略失敗: {err}"),
        }),
    }
}

fn parse_chain(raw: &str) -> Result<ChainKind, HttpResponse> {
    let normalized = raw.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "INPUT" => Ok(ChainKind::Input),
        "FORWARD" => Ok(ChainKind::Forward),
        "OUTPUT" => Ok(ChainKind::Output),
        _ => Err(HttpResponse::BadRequest().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "Chain 必須為 INPUT/FORWARD/OUTPUT".into(),
        })),
    }
}

fn parse_verdict(raw: &str) -> Result<Verdict, HttpResponse> {
    let normalized = raw.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "ACCEPT" => Ok(Verdict::Accept),
        "DROP" => Ok(Verdict::Drop),
        "REJECT" => Ok(Verdict::Reject),
        _ => Err(HttpResponse::BadRequest().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "Target/Policy 必須為 ACCEPT/DROP/REJECT".into(),
        })),
    }
}

fn parse_status(raw: &str) -> Result<GrpcFirewallStatus, HttpResponse> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "active" => Ok(GrpcFirewallStatus::Active),
        "inactive" => Ok(GrpcFirewallStatus::Inactive),
        _ => Err(HttpResponse::BadRequest().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "Status 必須為 active/inactive".into(),
        })),
    }
}

fn convert_firewall_status(
    resp: restful::GetFirewallResponse,
) -> Result<FirewallStatusResponse, String> {
    let status = match GrpcFirewallStatus::try_from(resp.status)
        .unwrap_or(GrpcFirewallStatus::Unspecified)
    {
        GrpcFirewallStatus::Active => ApiFirewallStatus::Active,
        GrpcFirewallStatus::Inactive => ApiFirewallStatus::Inactive,
        _ => return Err("未知的防火牆狀態".into()),
    };

    let chains = resp
        .chains
        .into_iter()
        .map(|chain| {
            let policy = map_verdict_enum(chain.policy)?;
            let mut rules_vec = Vec::new();
            for r in chain.rules {
                let target = map_verdict_enum(r.target)?;
                rules_vec.push(Rule {
                    target,
                    protocol: r.protocol,
                    in_if: r.in_if,
                    out_if: r.out_if,
                    source: r.source,
                    destination: r.destination,
                    options: r.options,
                });
            }
            Ok(Chain {
                name: chain.name,
                policy,
                rules_length: chain.rules_length as usize,
                rules: rules_vec,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(FirewallStatusResponse { status, chains })
}

fn map_verdict_enum(v: i32) -> Result<Target, String> {
    match Verdict::try_from(v).unwrap_or(Verdict::Unspecified) {
        Verdict::Accept => Ok(Target::Accept),
        Verdict::Drop => Ok(Target::Drop),
        Verdict::Reject => Ok(Target::Reject),
        _ => Err("未知的 Target/Policy 值".into()),
    }
}

fn to_response_result(result: Option<common::ActionResult>) -> ResponseResult {
    let default_err = ResponseResult { r#type: ResponseType::Err, message: "未知錯誤".into() };
    if let Some(res) = result {
        let rtype =
            match action_result::Type::try_from(res.r#type).unwrap_or(action_result::Type::Err) {
                action_result::Type::Ok => ResponseType::Ok,
                action_result::Type::Err => ResponseType::Err,
                _ => ResponseType::Err,
            };
        ResponseResult { r#type: rtype, message: res.message }
    } else {
        default_err
    }
}
