use config::Config;
use grpc::client::Client;
#[tokio::main]
async fn main() {
    let config = Config::default();
    let message = "Hello, gRPC!";
    let mut client = Client::connect(&config.addr).await.unwrap();
    let health = client.check_health().await.unwrap();
    println!("{:#?}", health);
    let response = client.send_message(message).await.unwrap();
    println!("收到回應：{:#?}", response);
}
