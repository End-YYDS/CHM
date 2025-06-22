#![allow(unused)]
use grpc::tonic::client;
use grpc::tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use grpc::tonic_health::pb::{health_client::HealthClient, HealthCheckRequest};
use grpc::{
    ca::{ca_client::CaClient, CsrRequest},
    tonic,
};
use openssl::x509::X509;
use std::collections::HashMap;
use std::fs;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.iter().all(|arg| arg != "--help" && arg != "-h") && args.len() < 2 {
        eprintln!("Usage: {} [--help | -h]", args[0]);
        eprintln!("Example: {} [--grpc | --web]", args[0]);
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--grpc") {
        let channel = init_grpc_connect().await?;
        // health_check(channel.clone()).await?;
        let error_channel = init_error_grpc_connect().await?;
        // health_check(error_channel.clone()).await?;
        // let grpc_client = CaClient::new(channel);
        let error_grpc_client = CaClient::new(error_channel);
        // test_crl(client.clone()).await?;
        // sign_cert(client.clone()).await?;
        // test_grpc_restart(grpc_client.clone()).await?;
        test_grpc_restart(error_grpc_client.clone()).await?;

        return Ok(());
    }
    if args.iter().any(|arg| arg == "--web") {
        // 初始化Web客戶端
        let web_client = init_http_connect().await?;
        test_first_controller_connect(&web_client).await?;
    }
    Ok(())
}

async fn sign_cert(mut client: CaClient<Channel>) -> Result<()> {
    let resp = client
        .sign_csr(grpc::ca::CsrRequest {
            csr: std::fs::read("certs/intermediateCA.csr")?,
            days: 365,
        })
        .await?;
    let reply = resp.into_inner();
    let leaf = openssl::x509::X509::from_der(&reply.cert)?;
    let leaf_pem = leaf.to_pem()?;
    println!("Leaf PEM:\n{}", String::from_utf8(leaf_pem.clone())?);
    Ok(())
}

async fn health_check(channel: Channel) -> Result<()> {
    let mut health = HealthClient::new(channel.clone());
    let resp = health
        .check(HealthCheckRequest {
            service: "ca.CA".into(),
        })
        .await?
        .into_inner();
    println!("ca.CA health status = {:?}", resp.status());
    Ok(())
}

async fn test_crl(mut client: CaClient<Channel>) -> Result<()> {
    let resp = client
        .sign_csr(CsrRequest {
            csr: std::fs::read("certs/intermediateCA.csr")?,
            days: 365,
        })
        .await?;
    let reply = resp.into_inner();
    let leaf = X509::from_der(&reply.cert)?;
    let leaf_pem = leaf.to_pem()?;
    println!("Leaf PEM:\n{}", String::from_utf8(leaf_pem.clone())?);
    fs::write("certs/test.pem", leaf_pem)?;
    Ok(())
}

async fn test_grpc_restart(mut client: CaClient<Channel>) -> Result<()> {
    // 模擬憑證更新
    let resp = client.reload_ca(grpc::ca::Empty {}).await?.into_inner();
    if resp.success {
        println!("gRPC CA 重啟成功");
    } else {
        println!("gRPC CA 重啟失敗");
    }
    Ok(())
}
async fn init_grpc_connect() -> Result<Channel> {
    let ca_cert = fs::read("certs/rootCA.pem")?;
    let ca_certificate = Certificate::from_pem(ca_cert);

    let grpc_test = fs::read("certs/grpc_test.pem")?;
    let grpc_test_pri = fs::read("certs/grpc_test.key")?;
    let grpc_test_identity = tonic::transport::Identity::from_pem(grpc_test, grpc_test_pri);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_certificate)
        .identity(grpc_test_identity);
    let channel = Endpoint::from_static("https://127.0.0.1:50052")
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(channel)
}

async fn init_http_connect() -> Result<reqwest::Client> {
    let mut client_pem = Vec::new();
    client_pem.extend(std::fs::read("certs/grpc_test.pem")?);
    client_pem.extend(std::fs::read("certs/grpc_test.key")?);
    let identity = reqwest::Identity::from_pem(&client_pem)?;
    let ca = std::fs::read("certs/rootCA.crt")?;
    let ca_cert = reqwest::Certificate::from_pem(&ca)?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    Ok(client)
}

async fn test_first_controller_connect(client: &reqwest::Client) -> Result<()> {
    println!("Testing first controller connect...");
    println!("OTP code: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let mut map = HashMap::new();
    map.insert("code", input.trim());
    let resp = client
        .post("https://127.0.0.1:50052/init")
        .json(&map)
        .send()
        .await?
        .error_for_status()?;
    let status: reqwest::StatusCode = resp.status();
    let body: String = resp.text_with_charset("utf-8").await?;

    // 5. 输出
    println!("Response Status: {}", status); // e.g. 200 OK
    println!("Response Body:\n{}", body);
    Ok(())
}

async fn init_error_grpc_connect() -> Result<Channel> {
    let ca_cert = fs::read("certs/rootCA.pem")?;
    let ca_certificate = Certificate::from_pem(ca_cert);

    let grpc_test = fs::read("certs/one_test.pem")?;
    let grpc_test_pri = fs::read("certs/one_test.key")?;
    let grpc_test_identity = tonic::transport::Identity::from_pem(grpc_test, grpc_test_pri);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_certificate)
        .identity(grpc_test_identity);
    let channel = Endpoint::from_static("https://127.0.0.1:50052")
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(channel)
}
