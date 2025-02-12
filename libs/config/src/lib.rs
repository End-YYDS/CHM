use std::net::{IpAddr, SocketAddr};

pub struct Config {
    pub ip: IpAddr,
    pub port: u16,
    pub addr: String,
}
impl Default for Config {
    fn default() -> Self {
        dotenv::dotenv().ok();
        let ip = std::env::var("IP").expect("IP is not set");
        let port = std::env::var("PORT").expect("PORT is not set");
        let addr = format!("{}:{}", ip, port);
        Self {
            ip: ip.parse().unwrap(),
            port: port.parse().unwrap(),
            addr,
        }
    }
}
impl Config {
    pub fn new(addr: &str) -> Self {
        let socket_addr: SocketAddr = addr.parse().expect("IP is not set");
        let ip: IpAddr = socket_addr.ip();
        let port = socket_addr.port();
        Self {
            ip,
            port,
            addr: addr.to_string(),
        }
    }
}
