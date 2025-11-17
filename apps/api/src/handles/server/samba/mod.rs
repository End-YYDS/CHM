use actix_web::{get, post, web};

use crate::{
    commons::{
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::samba::{
        logs::{
            samba_log::{Level, Samba_log},
            Logs,
        },
        shares::Shares,
        types::SambaResponse,
    },
};

mod logs;
mod shares;
mod types;

#[get("")]
async fn samba_root(_data: web::Json<UuidRequest>) -> web::Json<SambaResponse> {
    let _ = _data;
    web::Json(generate_test_samba_response())
}

fn generate_test_samba_response() -> SambaResponse {
    SambaResponse {
        common_info: CommonInfo {
            hostname: "samba-server-01".to_string(),
            status:   Status::Active,
            cpu:      10.5,
            memory:   2048.0,
        },
        connections: 15,
        shares:      vec![
            Shares {
                name:        "Public".to_string(),
                path:        "/srv/samba/public".to_string(),
                users:       5,
                permissions: "read, write".to_string(),
                status:      crate::handles::server::samba::shares::Status::active,
            },
            Shares {
                name:        "Private".to_string(),
                path:        "/srv/samba/private".to_string(),
                users:       2,
                permissions: "read".to_string(),
                status:      crate::handles::server::samba::shares::Status::inactive,
            },
        ],
        logs:        Logs {
            samba_log:        vec![Samba_log {
                date:    Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   22,
                    week:  Week::Fri,
                    time:  Time { hour: 14, min: 30 },
                },
                client:  "192.168.1.100:445".to_string(),
                event:   "Access granted to Public share".to_string(),
                level:   Level::info,
                message: "User 'guest' accessed the Public share.".to_string(),
            }],
            samba_log_length: 1,
        },
    }
}

pub fn samba_scope() -> actix_web::Scope {
    actix_web::web::scope("/samba").service(samba_root).service(action_scope())
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
