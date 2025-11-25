mod logs;
mod types;

use actix_web::{get, post, web};

use crate::{
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::ldap::{
        logs::{
            acc_log::{Access_log, Method, Protocol},
            Logs,
        },
        types::LDAPResponse,
    },
};

#[get("")]
async fn ldap_root(data: web::Json<UuidRequest>) -> web::Json<LDAPResponse> {
    dbg!(data);
    web::Json(generate_test_ldap_response())
}

/// 產生測試用 LDAPResponse 資料
fn generate_test_ldap_response() -> LDAPResponse {
    LDAPResponse {
        common_info: CommonInfo {
            hostname: "ldap-server-01".to_string(),
            status:   Status::Active,
            cpu:      2.2,
            memory:   512.0,
            ip:       None,
        },
        connections: 42,
        entries:     128,
        logs:        Logs {
            log_count:  vec![Error_log {
                date:    Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 15, min: 20 },
                },
                module:  "auth".to_string(),
                level:   Level::info,
                pid:     1234,
                client:  "192.168.1.100".to_string(),
                message: "Authentication succeeded".to_string(),
            }],
            errlength:  1,
            access_log: vec![Access_log {
                ip:               "192.168.1.101".to_string(),
                method:           Method::BIND,
                base_dn:          "dc=example,dc=com".to_string(),
                filter:           "(uid=admin)".to_string(),
                protocol:         Protocol::LDAPv3,
                status:           crate::handles::server::ldap::logs::acc_log::Status::Success,
                response_time_ms: 12,
                date:             Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 15, min: 21 },
                },
            }],
            acclength:  1,
        },
    }
}

pub fn ldap_scope() -> actix_web::Scope {
    actix_web::web::scope("/ldap").service(ldap_root).service(action_scope())
}

fn action_scope() -> actix_web::Scope {
    web::scope("/action").service(action_start).service(action_stop).service(action_restart)
}

#[post("/start")]
async fn action_start(data: web::Json<UuidRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "start successful".to_string() })
}

#[post("/stop")]
async fn action_stop(data: web::Json<UuidRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "stop successful".to_string() })
}

#[post("/restart")]
async fn action_restart(data: web::Json<UuidRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "restart successful".to_string(),
    })
}
