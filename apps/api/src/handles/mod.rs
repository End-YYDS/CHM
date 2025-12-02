use actix_web::web::ServiceConfig;

pub mod chm;
pub mod config;
pub mod cron;
pub mod file;
pub mod firewall;
pub mod info;
pub mod login;
pub mod logout;
pub mod logs;
pub mod network;
pub mod process;
pub mod server;
pub mod software;

pub fn handles_scope(cfg: &mut ServiceConfig) {
    cfg.service(login::login_scope())
        .service(logout::logout_scope())
        .service(server::server_scope())
        .service(chm::chm_scope())
        .service(cron::cron_scope())
        .service(info::info_scope())
        .service(config::config_scope())
        .service(file::file_scope())
        .service(logs::logs_scope())
        .service(firewall::firewall_scope())
        .service(network::network_scope())
        .service(process::process_scope())
        .service(software::software_scope());
}
