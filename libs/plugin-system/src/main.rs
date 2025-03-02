use config::get_config_manager;
use plugin_system::plugin_system_rest_server_handle;
#[actix_web::main]
async fn main() {
    let cmg = get_config_manager(false);
    match plugin_system_rest_server_handle(cmg).await {
        Ok(server) => {
            if let Err(e) = server.await {
                eprintln!("Server encountered an error: {}", e);
            }
        }
        Err(e) => eprintln!("Failed to initialize server: {}", e),
    }
}
