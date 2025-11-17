pub mod backup;
pub mod group;
pub mod mca;
pub mod pc_manager;
pub mod role;
pub mod setting;
pub mod user;

pub fn chm_scope() -> actix_web::Scope {
    actix_web::web::scope("/chm")
        .service(backup::backup_scope())
        .service(mca::mca_scope())
        .service(pc_manager::pc_manager_scope())
        .service(pc_manager::pcgroup_scope())
        .service(role::role_scope())
        .service(setting::setting_scope())
        .service(user::user_scope())
        .service(group::group_scope())
}
