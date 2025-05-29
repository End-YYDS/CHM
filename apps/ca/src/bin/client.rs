use std::fs;

// use ca::{grpc::ca_client::CaClient, grpc::CsrRequest, *};
// use openssl::x509::X509;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic_health::pb::{health_client::HealthClient, HealthCheckRequest};
// #[tokio::main]
// async fn main() -> anyhow::Result<()> {
//     // let mut client = CaClient::connect("http://127.0.0.1:50052").await?;
//     // let resp = client
//     //     .sign_csr(CsrRequest {
//     //         csr: std::fs::read("certs/intermediateCA.csr")?,
//     //     })
//     //     .await?;
//     // let reply = resp.into_inner();
//     // let leaf = X509::from_der(&reply.cert)?;
//     // let leaf_pem = leaf.to_pem()?;
//     // println!("Leaf PEM:\n{}", String::from_utf8(leaf_pem.clone())?);
//     // fs::write("certs/test.pem", leaf_pem)?;

//     let plain_channel = Channel::from_static("http://127.0.0.1:50052")
//         .connect()
//         .await?;
//     let mut plain_health = HealthClient::new(plain_channel);

//     let plain_response = plain_health
//         .check(HealthCheckRequest { service: "ca.CA".into() })
//         .await?
//         .into_inner();
//     println!("[Plain] ca.CA health status = {:?}", plain_response.status());

//     Ok(())
// }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CA 的rootCA
    let ca_cert = fs::read("certs/rootCA.pem")?;
    let ca_certificate = Certificate::from_pem(ca_cert);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_certificate);
        // .domain_name("127.0.0.1");
    let channel = Endpoint::from_static("https://127.0.0.1:50052")
        .tls_config(tls)?
        .connect()
        .await?;
    let mut health = HealthClient::new(channel);
    let resp = health
        .check(HealthCheckRequest {
            service: "ca.CA".into(),
        })
        .await?
        .into_inner();

    println!("ca.CA health status = {:?}", resp.status());
    Ok(())
}
