use dotenv::dotenv;
#[derive(Default)]
pub struct Config {
    pub ip: String,
    pub port: String,
    pub addr: String,
}

impl Config {
    pub fn new() -> Self {
        dotenv().ok();
        let ip = std::env::var("IP").expect("IP is not set");
        let port = std::env::var("PORT").expect("PORT is not set");
        let addr = format!("{}:{}", ip, port);
        Self { ip, port, addr }
    }
}
