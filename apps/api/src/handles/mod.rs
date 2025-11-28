use actix_web::web::ServiceConfig;

pub mod chm;
mod config;
mod cron;
mod file;
mod firewall;
mod info;
pub mod login;
pub mod logout;
mod logs;
mod network;
mod process;
pub mod server;
mod software;

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
