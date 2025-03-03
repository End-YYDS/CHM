use grpc::client::Client;
#[tokio::main]
async fn main() {
    let cmg = config::get_config_manager(None);
    let addr = cmg.get_grpc_service_ip("controller");
    let addr1 = cmg.get_grpc_service_ip("ca");
    let message = "Hello, gRPC!";
    let mut client = Client::connect(addr).await.unwrap();
    let mut client1 = Client::connect(addr1).await.unwrap();
    let health = client.check_health().await.unwrap();
    let health1 = client1.check_health().await.unwrap();
    println!("{:#?}", health);
    println!("{:#?}", health1);
    let response = client.send_message(message).await.unwrap();
    let response1 = client1.send_message(message).await.unwrap();
    println!("收到回應：{:#?}", response);
    println!("收到回應：{:#?}", response1);
}
