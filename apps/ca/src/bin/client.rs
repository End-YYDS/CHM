use grpc::tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use grpc::tonic_health::pb::{health_client::HealthClient, HealthCheckRequest};
use grpc::{
    ca::{ca_client::CaClient, CsrRequest},
    tonic,
};
use openssl::x509::X509;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CA 的rootCA
    let ca_cert = fs::read("certs/rootCA.pem")?;
    let ca_certificate = Certificate::from_pem(ca_cert);

    let grpc_test = fs::read("certs/grpc_test.pem")?;
    // let grpc_test_certificate = Certificate::from_pem(grpc_test);
    let grpc_test_pri = fs::read("certs/grpc_test.key")?;
    let grpc_test_identity = tonic::transport::Identity::from_pem(grpc_test, grpc_test_pri);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_certificate)
        .identity(grpc_test_identity);
    // .domain_name("127.0.0.1");
    let channel = Endpoint::from_static("https://127.0.0.1:50052")
        .tls_config(tls)?
        .connect()
        .await?;
    let mut health = HealthClient::new(channel.clone());
    let resp = health
        .check(HealthCheckRequest {
            service: "ca.CA".into(),
        })
        .await?
        .into_inner();

    println!("ca.CA health status = {:?}", resp.status());
    let mut client = CaClient::new(channel);
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
