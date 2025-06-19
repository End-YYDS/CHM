#![allow(unused)]
use grpc::tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use grpc::tonic_health::pb::{health_client::HealthClient, HealthCheckRequest};
use grpc::{
    ca::{ca_client::CaClient, CsrRequest},
    tonic,
};
use openssl::x509::X509;
use std::fs;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> Result<()> {
    let channel = init_connect().await?;

    health_check(channel.clone()).await?;

    // let client = CaClient::new(channel);
    // test_crl(client.clone()).await?;
    // sign_cert(client.clone()).await?;
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

async fn init_connect() -> Result<Channel> {
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
