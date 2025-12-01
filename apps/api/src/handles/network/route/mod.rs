mod types;

use actix_web::{delete, get, patch, post, put, web, HttpResponse, Scope};
use std::collections::HashMap;

use crate::commons::{ResponseResult, ResponseType};
use types::*;

pub fn route_scope() -> Scope {
    web::scope("/route")
        .service(_get_route_all)
        .service(_post_route_root)
        .service(_delete_route_root)
        .service(_patch_route_root)
        .service(_put_route_root)
}

/// GET /api/network/route
#[get("")]
async fn _get_route_all() -> HttpResponse {
    let mut routes = HashMap::new();
    routes.insert(
        "0.0.0.0/0".into(),
        RouteItem {
            via:    "192.168.1.1".into(),
            dev:    "eth0".into(),
            proto:  "dhcp".into(),
            metric: 100,
            scope:  "global".into(),
            src:    "192.168.1.10".into(),
        },
    );
    let pc_routes = PcRoutes { length: routes.len(), routes };

    let mut pcs = HashMap::new();
    pcs.insert("uuid-a".into(), pc_routes);

    HttpResponse::Ok().json(GetAllRouteResponse { length: pcs.len(), pcs })
}

/// POST /api/network/route
#[post("")]
async fn _post_route_root(data: web::Json<CreateRouteRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Route added".into() })
}

/// DELETE /api/network/route
#[delete("")]
async fn _delete_route_root(data: web::Json<DeleteRouteRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Route deleted".into() })
}

/// PATCH /api/network/route
#[patch("")]
async fn _patch_route_root(data: web::Json<PatchRouteRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Route updated (partial)".into(),
    })
}

/// PUT /api/network/route
#[put("")]
async fn _put_route_root(data: web::Json<PutRouteRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Route replaced".into() })
}
