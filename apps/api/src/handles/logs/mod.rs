use actix_web::{web, Scope};

pub mod pc;
pub mod sys;

pub fn logs_scope() -> Scope {
    web::scope("/logs").service(sys::sys_scope()).service(pc::pc_scope())
}
