use reqwest::ClientBuilder;
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    println!("請輸入初始化 OTP:");
    std::io::stdin().read_line(&mut input)?;
    let otp = input.trim();
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let base_url = "https://127.0.0.1:50050/init";
    let root_pem = std::fs::read("../../../../certs/rootCA.pem")?.to_vec();
    let resp = client
        .post(base_url)
        .json(&serde_json::json!({ "code": otp, "op": "bootstrap","root_ca_pem": root_pem}))
        .send()
        .await?;
    let json: Value = resp.json().await?;
    if let Some(csr_pem) = json.get("csr_pem") {
        if let Some(array) = csr_pem.as_array() {
            // 轉成 Vec<u8>
            let bytes: Vec<u8> = array.iter().filter_map(|v| v.as_u64()).map(|n| n as u8).collect();
            let pem = String::from_utf8_lossy(&bytes);
            println!("csr_pem:\n{pem}");
        } else if let Some(s) = csr_pem.as_str() {
            println!("csr_pem:\n{s}");
        } else {
            eprintln!("csr_pem 欄位格式不支援: {csr_pem:?}");
        }
    } else {
        eprintln!("回應中沒有 csr_pem 欄位: {json:?}");
    }
    Ok(())
}
