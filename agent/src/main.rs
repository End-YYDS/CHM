use config::Config;
use grpc::client::send_message;
#[tokio::main]
async fn main() {
    let config = Config::new();
    let message = "Hello, gRPC!";
    let response = send_message(&config.addr, message).await.unwrap();
    println!("收到回應：{:#?}", response);
}
