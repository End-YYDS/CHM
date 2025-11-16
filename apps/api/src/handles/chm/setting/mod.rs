mod ip;
mod module;
mod values;

use actix_web::{web, Scope};

pub fn setting_scope() -> Scope {
    web::scope("/setting")
        .service(module::module_scope())
        .service(ip::ip_scope())
        .service(values::values_scope())
}
