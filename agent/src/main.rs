use grpc::client::send_message;
#[tokio::main]
async fn main() {
    println!("Hello, world!");
    let addr = "[::1]:50051";
    let message = "Hello, gRPC!";
    let response = send_message(addr, message).await.unwrap();
    println!("收到回應：{:#?}", response);
}
