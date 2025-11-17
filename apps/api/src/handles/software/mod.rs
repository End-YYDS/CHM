mod types;

use actix_web::{delete, get, post, web, HttpResponse, Scope};
use std::collections::HashMap;

use types::*;

pub fn software_scope() -> Scope {
    web::scope("/software").service(_get_software).service(_post_software).service(_delete_software)
}

/// GET /api/software
#[get("")]
async fn _get_software() -> HttpResponse {
    let mut pkgs = HashMap::new();
    pkgs.insert(
        "nginx".into(),
        PackageInfo { version: "1.20.0".into(), status: PackageStatus::Installed },
    );
    pkgs.insert(
        "redis".into(),
        PackageInfo { version: "7.0".into(), status: PackageStatus::Notinstall },
    );

    let mut pcs = HashMap::new();
    pcs.insert("uuid-a".into(), PcPackages { packages: pkgs });

    HttpResponse::Ok().json(GetSoftwareResponse { pcs })
}

/// POST /api/software
#[post("")]
async fn _post_software(data: web::Json<InstallRequest>) -> HttpResponse {
    dbg!(&data);

    let mut map = HashMap::new();
    map.insert(
        "nginx".into(),
        PackageActionResult {
            installed:    vec!["uuid-a".into()],
            notinstalled: vec!["uuid-b".into()],
        },
    );

    HttpResponse::Ok().json(ActionResponse { length: map.len(), packages: map })
}

/// DELETE /api/software
#[delete("")]
async fn _delete_software(data: web::Json<DeleteRequest>) -> HttpResponse {
    dbg!(&data);

    let mut map = HashMap::new();
    map.insert(
        "redis".into(),
        PackageActionResult {
            installed:    vec!["uuid-a".into()],
            notinstalled: vec!["uuid-b".into()],
        },
    );

    HttpResponse::Ok().json(ActionResponse { length: map.len(), packages: map })
}
