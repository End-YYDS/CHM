use std::fs;

use ca::{grpc::ca_client::CaClient, grpc::CsrRequest, *};
use openssl::x509::X509;
#[tokio::main]
async fn main() -> CaResult<()> {
    let mut client = CaClient::connect("http://127.0.0.1:50052").await?;
    let resp = client
        .sign_csr(CsrRequest {
            csr: std::fs::read("certs/intermediateCA.csr")?,
        })
        .await?;
    let reply = resp.into_inner();
    let leaf = X509::from_der(&reply.cert)?;
    let leaf_pem = leaf.to_pem()?;
    println!("Leaf PEM:\n{}", String::from_utf8(leaf_pem.clone())?);
    fs::write("certs/test.pem", leaf_pem)?;

    Ok(())
}
