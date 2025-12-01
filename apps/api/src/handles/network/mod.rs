use actix_web::{web, Scope};

pub mod dns;
pub mod net;
pub mod route;

pub fn network_scope() -> Scope {
    web::scope("/network")
        .service(net::net_scope())
        .service(route::route_scope())
        .service(dns::dns_scope())
}
