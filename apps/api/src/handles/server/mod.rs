use actix_web::{get, post, web};
use std::collections::HashMap;

use crate::{
    commons::{CommonInfo, ResponseResult, ResponseType, Status},
    handles::server::{
        apache::apache_scope,
        bind::bind_scope,
        dhcp::dhcp_scope,
        ftp::ftp_scope,
        ldap::ldap_scope,
        mysql::mysql_scope,
        nginx::nginx_scope,
        samba::samba_scope,
        squid::squid_scope,
        ssh::ssh_scope,
        stall::{stall_request, stalledResponse, stalled_request, Pcs},
    },
};

mod apache;
mod bind;
mod dhcp;
mod ftp;
mod ldap;
mod mysql;
mod nginx;
mod samba;
mod squid;
mod ssh;
mod stall;

pub fn server_scope() -> actix_web::Scope {
    web::scope("/server")
        .service(apache_scope())
        .service(bind_scope())
        .service(dhcp_scope())
        .service(ldap_scope())
        .service(mysql_scope())
        .service(nginx_scope())
        .service(ftp_scope())
        .service(samba_scope())
        .service(squid_scope())
        .service(ssh_scope())
        .service(installed)
        .service(noinstall)
        .service(install)
}

#[get("/installed")]
async fn installed(data: web::Json<stalled_request>) -> web::Json<stalledResponse> {
    let server_name = &data.server;
    // Example test data
    let mut data: HashMap<String, CommonInfo> = HashMap::new();
    let test = CommonInfo {
        hostname: format!("{server_name}-install-host"),
        status:   Status::Active,
        cpu:      0.0,
        memory:   0.0,
    };
    data.insert(String::from("server_name"), test);
    let pcs = Pcs { uuids: data };
    let length = pcs.uuids.len();
    let response = stalledResponse { pcs, length };
    web::Json(response)
}

#[get("/noinstall")]
async fn noinstall(data: web::Json<stalled_request>) -> web::Json<stalledResponse> {
    let server_name = &data.server;
    let test = CommonInfo {
        hostname: format!("{server_name}-noinstall-host"),
        status:   Status::Stopped,
        cpu:      0.0,
        memory:   0.0,
    };
    let mut data = HashMap::new();
    data.insert(String::from("server_name"), test);
    // Example test data
    let pcs = Pcs { uuids: data };
    let length = pcs.uuids.len();
    let response = stalledResponse { pcs, length };
    web::Json(response)
}

#[post("/install")]
async fn install(data: web::Json<stall_request>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "install successful".to_string(),
    })
}
