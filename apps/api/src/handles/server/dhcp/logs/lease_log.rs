use serde::Serialize;

use crate::commons::Date;

#[derive(Debug, Serialize)]
pub enum Action {
    Offer,
    Ack,
    Decline,
    Release,
    Inform,
}

#[derive(Debug, Serialize)]
pub struct Lease_log {
    #[serde(rename = "Client_IP")]
    pub client_ip:  String,
    #[serde(rename = "MAC")]
    pub mac:        String,
    #[serde(rename = "Date")]
    pub date:       Date,
    #[serde(rename = "Action")]
    pub action:     Action,
    #[serde(rename = "Lease_Time")]
    pub lease_time: i64,
    #[serde(rename = "Server_IP")]
    pub server_ip:  String,
    #[serde(rename = "Message")]
    pub message:    String,
}
