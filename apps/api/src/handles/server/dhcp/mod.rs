use actix_web::{get, post, web};

use crate::{
    commons::{ResponseResult, ResponseType, UuidRequest},
    handles::server::dhcp::types::DHCPResponse,
};

mod logs;
mod types;

#[get("")]
async fn dhcp_root(data: web::Json<UuidRequest>) -> web::Json<DHCPResponse> {
    dbg!(data);
    web::Json(generate_test_dhcp_response())
}

/// 產生測試用 DHCPResponse 資料
fn generate_test_dhcp_response() -> DHCPResponse {
    use crate::{
        commons::{
            error_logs::{Error_log, Level},
            CommonInfo, Date, Month, Status, Time, Week,
        },
        handles::server::dhcp::logs::{
            lease_log::{Action, Lease_log},
            Logs,
        },
    };

    DHCPResponse {
        common_info: CommonInfo {
            hostname: "dhcp-server-01".to_string(),
            status:   Status::Active,
            cpu:      1.8,
            memory:   256.0,
            ip:       None,
        },
        leases:      15,
        logs:        Logs {
            error_log:  vec![Error_log {
                date:    Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 15, min: 10 },
                },
                module:  "lease".to_string(),
                level:   Level::info,
                pid:     5678,
                client:  "192.168.1.200".to_string(),
                message: "Lease granted".to_string(),
            }],
            errlength:  1,
            lease_log:  vec![Lease_log {
                client_ip:  "192.168.1.201".to_string(),
                mac:        "AA:BB:CC:DD:EE:FF".to_string(),
                date:       Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 15, min: 11 },
                },
                action:     Action::Offer,
                lease_time: 3600,
                server_ip:  "192.168.1.1".to_string(),
                message:    "Lease offer sent".to_string(),
            }],
            leaslength: 1,
        },
    }
}

pub fn dhcp_scope() -> actix_web::Scope {
    actix_web::web::scope("/dhcp").service(dhcp_root).service(action_scope())
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
    println!("{data:#?}");
    println!("{data:#?}");
    println!("{data:#?}");
    println!("{data:#?}");
    println!("{data:#?}");
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "restart successful".to_string(),
    })
}
