#![allow(unused)]
use chrono::{DateTime, Duration, Local, Utc};
use grpc::ca::CertStatus;
use grpc::crl::crl_client::CrlClient;
use grpc::crl::{ListCrlEntriesRequest, ListCrlEntriesResponse};
use grpc::prost::Message;
use grpc::prost_types::Timestamp;
use grpc::tonic::client;
use grpc::tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use grpc::tonic_health::pb::{health_client::HealthClient, HealthCheckRequest};
use grpc::{
    ca::{ca_client::CaClient, CsrRequest},
    tonic,
};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::X509;
use std::collections::HashMap;
use std::fs;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct Info {
    root_ca: &'static str,
    private: &'static str,
    cert: &'static str,
    url: &'static str,
    // one_test_private: &'static str,
    // one_test_cert: &'static str,
}
// const INFO: Info = Info {
//     root_ca: "certs/rootCA.pem",
//     private: "certs/grpc_test.key",
//     cert: "certs/grpc_test.pem",
//     url: "https://127.0.0.1:50052",
//     one_test_private: "certs/one_test.key",
//     one_test_cert: "certs/one_test.pem",
// };

#[tokio::main]
async fn main() -> Result<()> {
    let info: Info = Info {
        root_ca: "certs/rootCA.pem",
        private: "certs/grpc_test.key",
        cert: "certs/grpc_test.pem",
        url: "https://127.0.0.1:50052",
    };
    let info1 = Info {
        private: "certs/one_test.key",
        cert: "certs/one_test.pem",
        ..info
    };
    let info2 = Info {
        private: "certs/mini_controller.key",
        cert: "certs/mini_controller.pem",
        ..info
    };
    let args = std::env::args().collect::<Vec<_>>();
    if args.iter().all(|arg| arg != "--help" && arg != "-h") && args.len() < 2 {
        eprintln!("Usage: {} [--help | -h]", args[0]);
        eprintln!("Example: {} [--grpc | --web]", args[0]);
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--debug") {
        dbg!(&info);
        dbg!(&info1);
    }
    if args.iter().any(|arg| arg == "--grpc") {
        // GRPC 連接測試
        let channel = init_grpc(&info1).await?;
        // 健康檢查
        health_check(channel.clone()).await?;
        // GRPC 測試
        let grpc_client = CaClient::new(channel.clone());
        // sign_cert(grpc_client.clone()).await?;
        // test_grpc_restart(grpc_client.clone()).await?;

        // get_all_certs(grpc_client.clone()).await?;
        // get_cert_by_serial(
        //     grpc_client.clone(),
        //     "6efa012bdf10f10b7bba8329b7b7c604c0201236cef251a6149d9fdad8b3a640",
        // )
        // .await?;
        // get_cert_by_thumbprint(
        //     grpc_client.clone(),
        //     "1d56a030c918fcfb8b90f3dbd5e572fb44071270d96aecd494ef2754bf5e304d",
        // )
        // .await?;
        // get_cert_status_by_serial(
        //     grpc_client.clone(),
        //     "6efa012bdf10f10b7bba8329b7b7c604c0201236cef251a6149d9fdad8b3a640",
        // )
        // .await?;
        // get_cert_by_common_name(grpc_client.clone(), "one.example.com").await?;

        mark_cert_revoked(
            grpc_client.clone(),
            "6efa012bdf10f10b7bba8329b7b7c604c0201236cef251a6149d9fdad8b3a640",
            Some("測試撤銷".to_string()),
        )
        .await?;

        // CRL 測試
        // let crl_client = CrlClient::new(channel.clone());
        // test_crl(crl_client.clone()).await?;

        return Ok(());
    }
    if args.iter().any(|arg| arg == "--web") {
        let web_client = init_http_connect(&info).await?;
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

async fn test_crl(mut client: CrlClient<Channel>) -> Result<()> {
    let to_timestamp = |dt: DateTime<Utc>| Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    };
    let from_timestamp =
        |ts: Timestamp| DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32);
    let to_local = |dt: Timestamp| {
        Some(
            DateTime::<Utc>::from_timestamp(dt.seconds, dt.nanos as u32)
                .unwrap()
                .with_timezone(&Local),
        )
    };
    let now: DateTime<Utc> = Utc::now();
    let since_dt = Utc::now() - Duration::days(5);
    let since = to_timestamp(since_dt);
    let resp = client
        .list_crl_entries(ListCrlEntriesRequest {
            since: Some(since),
            limit: 10,
            offset: 0,
        })
        .await?;
    // let resp = client
    //     .list_crl_entries(ListCrlEntriesRequest {
    //         since: None,
    //         limit: 10,
    //         offset: 0,
    //     })
    //     .await?;
    let reply = resp.into_inner();
    println!("CRL Entries: {:#?}", reply.entries);
    println!(
        "This Update: {:#?}, Next Update: {:#?}, CRL Number: {}",
        reply.this_update.and_then(to_local),
        reply.next_update.and_then(to_local),
        reply.crl_number
    );
    Ok(())
}

async fn test_grpc_restart(mut client: CaClient<Channel>) -> Result<()> {
    // 模擬憑證更新
    let resp = client.reload_grpc(grpc::ca::Empty {}).await?.into_inner();
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
async fn init_http_connect(info: &Info) -> Result<reqwest::Client> {
    let mut client_pem = Vec::new();
    client_pem.extend(std::fs::read(info.cert)?);
    client_pem.extend(std::fs::read(info.private)?);
    let identity = reqwest::Identity::from_pem(&client_pem)?;
    // let ca = std::fs::read("certs/rootCA.crt")?;
    let ca = std::fs::read(info.root_ca)?;
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

async fn init_grpc(info: &Info) -> Result<Channel> {
    let ca_cert = fs::read(info.root_ca)?;
    let ca_certificate = Certificate::from_pem(ca_cert);

    let grpc_test = fs::read(info.cert)?;
    let grpc_test_pri = fs::read(info.private)?;
    let grpc_test_identity = tonic::transport::Identity::from_pem(grpc_test, grpc_test_pri);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_certificate)
        .identity(grpc_test_identity);
    let channel = Endpoint::from_static(info.url)
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(channel)
}

pub fn verify_crl_signature(
    ca_cert: &X509,
    resp: &ListCrlEntriesResponse,
) -> std::result::Result<(), String> {
    let signature = resp.signature.as_slice();
    let mut clean = resp.clone();
    clean.signature = Vec::new();
    let raw = Message::encode_to_vec(&clean);
    let pubkey = ca_cert
        .public_key()
        .map_err(|e| format!("取公鑰失敗: {}", e))?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey)
        .map_err(|e| format!("建立 Verifier 失敗: {}", e))?;
    verifier
        .update(&raw)
        .map_err(|e| format!("Verifier update 失敗: {}", e))?;
    if verifier
        .verify(signature)
        .map_err(|e| format!("執行 verify 失敗: {}", e))?
    {
        Ok(())
    } else {
        Err("簽名驗證失敗：簽章不符".into())
    }
}

pub async fn get_all_certs(mut client: CaClient<Channel>) -> Result<()> {
    let resp = client.list_all(grpc::ca::Empty {}).await?;
    let reply = resp.into_inner();
    println!("All Certificates: {:?}", reply.certs);
    Ok(())
}

pub async fn get_cert_by_serial(
    mut client: CaClient<Channel>,
    serial: &str,
) -> Result<Option<grpc::ca::Cert>> {
    let resp = client
        .get(grpc::ca::GetCertRequest {
            serial: serial.to_string(),
        })
        .await?;
    let reply = resp.into_inner();
    if reply.cert.is_some() {
        println!("Found Certificate: {:?}", reply.cert);
    } else {
        println!("Certificate not found for serial: {}", serial);
    }
    Ok(reply.cert)
}

pub async fn get_cert_by_thumbprint(
    mut client: CaClient<Channel>,
    thumbprint: &str,
) -> Result<Option<grpc::ca::Cert>> {
    let resp = client
        .get_by_thumbprint(grpc::ca::GetByThumprintRequest {
            thumbprint: thumbprint.to_string(),
        })
        .await?;
    let reply = resp.into_inner();
    if reply.cert.is_some() {
        println!("Found Certificate by Thumbprint: {:?}", reply.cert);
    } else {
        println!("Certificate not found for thumbprint: {}", thumbprint);
    }
    Ok(reply.cert)
}

pub async fn get_cert_status_by_serial(
    mut client: CaClient<Channel>,
    serial: &str,
) -> Result<Option<grpc::ca::CertStatus>> {
    let resp = client
        .query_cert_status(grpc::ca::QueryCertStatusRequest {
            serial: serial.to_string(),
        })
        .await?;
    let reply = resp.into_inner();
    if reply.status.is_some() {
        let status = CertStatus::try_from(reply.status.unwrap())?;
        println!("Certificate Status: {:?}", status);
    } else {
        println!("Certificate status not found for serial: {}", serial);
        return Ok(None);
    }
    let status = CertStatus::try_from(reply.status.unwrap());
    Ok(status.ok())
}

pub async fn get_cert_by_common_name(
    mut client: CaClient<Channel>,
    common_name: &str,
) -> Result<Option<grpc::ca::Cert>> {
    let resp = client
        .get_by_common_name(grpc::ca::GetByCommonNameRequest {
            name: common_name.to_string(),
        })
        .await?;
    let reply = resp.into_inner();
    if reply.cert.is_some() {
        println!("Found Certificate by Common Name: {:?}", reply.cert);
    } else {
        println!("Certificate not found for common name: {}", common_name);
    }
    Ok(reply.cert)
}

pub async fn mark_cert_revoked(
    mut client: CaClient<Channel>,
    serial: &str,
    reason: Option<String>,
) -> Result<()> {
    let resp = client
        .mark_cert_revoked(grpc::ca::MarkCertRevokedRequest {
            serial: serial.to_string(),
            reason,
        })
        .await?;
    let reply = resp.into_inner();
    if reply.success {
        println!("Certificate {} marked as revoked", serial);
    } else {
        println!("Failed to mark certificate {} as revoked", serial);
    }
    Ok(())
}
