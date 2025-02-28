use config::Config;
use grpc::client::Client;
#[tokio::main]
async fn main() {
    let config = Config::default();
    let config1 = Config::new("[::1]:50052");
    let message = "Hello, gRPC!";
    let mut client = Client::connect(&config.addr).await.unwrap();
    let mut client1 = Client::connect(&config1.addr).await.unwrap();
    let health = client.check_health().await.unwrap();
    let health1 = client1.check_health().await.unwrap();
    println!("{:#?}", health);
    println!("{:#?}", health1);
    let response = client.send_message(message).await.unwrap();
    let response1 = client1.send_message(message).await.unwrap();
    println!("收到回應：{:#?}", response);
    println!("收到回應：{:#?}", response1);
}
