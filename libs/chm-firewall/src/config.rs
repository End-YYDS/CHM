use std::{fs, path::Path};

use anyhow::Result;
use nftables::types;
use serde::{Deserialize, Serialize};

use crate::nft::{BasicFirewallConfig, RuleAction};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct AppConfig {
    firewall: FirewallSection,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let contents = fs::read_to_string(path)?;
            Ok(toml::from_str(&contents)?)
        } else {
            Ok(Self::default())
        }
    }
    pub fn save(&mut self, path: &Path, hot_config: BasicFirewallConfig) -> Result<()> {
        self.firewall = hot_config.into();
        let toml_string = toml::to_string_pretty(self)?;
        fs::write(path, toml_string)?;
        Ok(())
    }
    pub fn get_firewall_config(&self) -> BasicFirewallConfig {
        self.firewall.clone().into()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct FirewallSection {
    pub enabled:            bool,
    pub family:             types::NfFamily,
    pub table:              String,
    pub input_chain:        String,
    pub output_chain:       String,
    pub default_priority:   i32,
    pub loopback_interface: String,
}

impl Default for FirewallSection {
    fn default() -> Self {
        Self {
            enabled:            true,
            family:             types::NfFamily::INet,
            table:              "chm_table".to_string(),
            input_chain:        "chm_input".to_string(),
            output_chain:       "chm_output".to_string(),
            default_priority:   0,
            loopback_interface: "lo".to_string(),
        }
    }
}

impl From<FirewallSection> for BasicFirewallConfig {
    fn from(section: FirewallSection) -> Self {
        BasicFirewallConfig {
            enabled:            section.enabled,
            family:             section.family,
            table:              section.table,
            input_chain:        section.input_chain,
            output_chain:       section.output_chain,
            default_priority:   section.default_priority,
            loopback_interface: section.loopback_interface,
            input_policy:       RuleAction::Drop,
            output_policy:      RuleAction::Accept,
        }
    }
}

impl From<BasicFirewallConfig> for FirewallSection {
    fn from(config: BasicFirewallConfig) -> Self {
        FirewallSection {
            enabled:            config.enabled,
            family:             config.family,
            table:              config.table,
            input_chain:        config.input_chain,
            output_chain:       config.output_chain,
            default_priority:   config.default_priority,
            loopback_interface: config.loopback_interface,
        }
    }
}
