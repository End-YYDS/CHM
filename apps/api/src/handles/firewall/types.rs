use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallStatus {
    Active,
    Inactive,
}

#[derive(Debug, Serialize)]
pub enum Target {
    #[serde(rename = "ACCEPT")]
    Accept,
    #[serde(rename = "DROP")]
    Drop,
    #[serde(rename = "REJECT")]
    Reject,
}

#[derive(Debug, Serialize)]
pub struct Rule {
    #[serde(rename = "Target")]
    pub target:      Target,
    #[serde(rename = "Protocol")]
    pub protocol:    String,
    #[serde(rename = "In")]
    pub in_if:       String,
    #[serde(rename = "Out")]
    pub out_if:      String,
    #[serde(rename = "Source")]
    pub source:      String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Options")]
    pub options:     String,
}

#[derive(Debug, Serialize)]
pub struct Chain {
    #[serde(rename = "Name")]
    pub name:         String,
    #[serde(rename = "Policy")]
    pub policy:       Target,
    #[serde(rename = "Rules")]
    pub rules:        Vec<Rule>,
    #[serde(rename = "Rules_Length")]
    pub rules_length: usize,
}

#[derive(Debug, Serialize)]
pub struct FirewallStatusResponse {
    #[serde(rename = "Status")]
    pub status: FirewallStatus,
    #[serde(rename = "Chains")]
    pub chains: Vec<Chain>,
}

/// DELETE /api/firewall/rule
#[derive(Debug, Deserialize)]
pub struct DeleteRuleRequest {
    #[serde(rename = "Uuid")]
    pub uuid:    String,
    #[serde(rename = "Chain")]
    pub chain:   String,
    #[serde(rename = "RuleId")]
    pub rule_id: i64,
}

/// PUT /api/firewall/status
#[derive(Debug, Deserialize)]
pub struct PutStatusRequest {
    #[serde(rename = "Uuid")]
    pub uuid:   String,
    #[serde(rename = "Status")]
    pub status: String,
}

/// PUT /api/firewall/policy
#[derive(Debug, Deserialize)]
pub struct PutPolicyRequest {
    #[serde(rename = "Uuid")]
    pub uuid:   String,
    #[serde(rename = "Chain")]
    pub chain:  String,
    #[serde(rename = "Policy")]
    pub policy: String,
}
/// POST /api/firewall/rule
#[derive(Debug, Deserialize)]
pub struct AddRuleRequest {
    #[serde(rename = "Uuid")]
    pub uuid:        String,
    #[serde(rename = "Chain")]
    pub chain:       String,
    #[serde(rename = "Target")]
    pub target:      String,
    #[serde(rename = "Protocol")]
    pub protocol:    String,
    #[serde(rename = "In")]
    pub in_if:       String,
    #[serde(rename = "Out")]
    pub out_if:      String,
    #[serde(rename = "Source")]
    pub source:      String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Options")]
    pub options:     String,
}
