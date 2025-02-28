mod env_settings;
mod manager;
mod types;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{
    dev::Server,
    http::{header::HeaderName, Method},
    middleware::{DefaultHeaders, Logger},
    web, App, HttpServer, Responder,
};
use console::Style;
use env_settings::{get_env, get_json_array};
use log::{info, LevelFilter};
use manager::PluginManager;

async fn get_routes(plugin_manager: web::Data<PluginManager>) -> impl Responder {
    plugin_manager.get_routes_json()
}
async fn list_plugins(manager: web::Data<PluginManager>) -> impl Responder {
    web::Json(manager.get_plugins_meta())
}

pub async fn plugin_system_rest_server_handle() -> std::io::Result<Server> {
    let domains = get_json_array("TRUSTED_DOMAINS");
    let origins = get_json_array("ALLOWED_ORIGINS");
    let allow_method = get_json_array("ALLOWED_METHODS")
        .iter()
        .filter_map(|m| m.parse::<Method>().ok())
        .collect::<Vec<Method>>();
    let allow_headers = get_json_array("ALLOWED_HEADERS")
        .iter()
        .filter_map(|h| h.parse::<HeaderName>().ok())
        .collect::<Vec<HeaderName>>();
    let cors_timeout = get_env("CORS_TIMEOUT", 3600);
    let csp = format!("script-src 'self' {}", domains.join(" "));
    let is_debug = get_env("DEBUG", false);
    let port = get_env("PORT", 8080);
    let ip = get_env("IP", "127.0.0.1".to_string());

    env_logger::builder()
        .filter_level(if is_debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        })
        .init();
    if is_debug {
        std::env::set_var("RUST_LOG", "actix_web=debug");
        info!("Debug mode enabled");
    } else {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    let plugin_dir = std::env::current_dir()?.join("plugins");
    if !plugin_dir.exists() {
        std::fs::create_dir_all(&plugin_dir)?;
    }
    let blue = Style::new().blue();
    let target = format!("{}:{}", ip, port);
    let mut manager = PluginManager::new(plugin_dir);
    manager.load_all_plugins()?;
    let plugin_manager = web::Data::new(manager);
    println!(
        "\nServer ready at {}",
        blue.apply_to(format!("http://{}", &target))
    );
    let server = HttpServer::new(move || {
        let origins_clone = origins.clone();
        let governor = GovernorConfigBuilder::default()
            .seconds_per_request(10)
            .burst_size(5)
            .finish()
            .unwrap();
        let cors = actix_cors::Cors::default()
            .allowed_origin_fn(move |origin, _req_head| {
                origins_clone
                    .iter()
                    .any(|allowed| allowed.as_bytes() == origin.as_bytes())
            })
            .allowed_methods(allow_method.clone())
            .allowed_headers(allow_headers.clone())
            .max_age(cors_timeout);
        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(Governor::new(&governor))
            .wrap(
                DefaultHeaders::new()
                    .add(("X-XSS-Protection", "1; mode=block"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                    .add(("Content-Security-Policy", csp.as_str()))
                    .add((
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    ))
                    .add((
                        "Permissions-Policy",
                        "geolocation=(), microphone=(), camera=()",
                    ))
                    .add(("Cross-Origin-Embedder-Policy", "require-corp"))
                    .add(("Cross-Origin-Opener-Policy", "same-origin"))
                    .add(("Cross-Origin-Resource-Policy", "same-site")),
            )
            .app_data(plugin_manager.clone())
            .service(
                web::scope("/api")
                    .configure(|cfg| plugin_manager.configure_routes(cfg))
                    .route("/routes", web::get().to(get_routes))
                    .route("/plugins", web::get().to(list_plugins)),
            )
    })
    .bind(&target)?
    .run();
    Ok(server)
}
