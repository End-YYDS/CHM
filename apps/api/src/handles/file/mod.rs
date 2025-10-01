use actix_web::{web, Scope};

pub mod pdir;
pub mod vdir;

pub fn file_scope() -> Scope {
    web::scope("/file").service(pdir::pdir_scope()).service(vdir::vdir_scope())
}
