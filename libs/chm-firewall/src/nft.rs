#![allow(dead_code)]
use anyhow::{bail, Result};
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix, CT},
    schema,
    stmt::{Accept, Drop, Match, Operator, Statement},
    types,
};
use std::{borrow::Cow, fs, path::Path};

use crate::config::AppConfig;

const DEFAULT_TABLE_NAME: &str = "chm_table";
const DEFAULT_INPUT_CHAIN_NAME: &str = "chm_input";
const DEFAULT_OUTPUT_CHAIN_NAME: &str = "chm_output";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum RuleAction {
    Accept,
    Drop,
}

impl From<RuleAction> for types::NfChainPolicy {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Accept => types::NfChainPolicy::Accept,
            RuleAction::Drop => types::NfChainPolicy::Drop,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BasicFirewallConfig {
    pub enabled:            bool,
    pub family:             types::NfFamily,
    pub table:              String,
    pub input_chain:        String,
    pub output_chain:       String,
    pub input_policy:       RuleAction,
    pub output_policy:      RuleAction,
    pub default_priority:   i32,
    pub loopback_interface: String,
}

impl Default for BasicFirewallConfig {
    fn default() -> Self {
        Self {
            enabled:            true,
            family:             types::NfFamily::INet,
            table:              DEFAULT_TABLE_NAME.to_string(),
            input_chain:        DEFAULT_INPUT_CHAIN_NAME.to_string(),
            output_chain:       DEFAULT_OUTPUT_CHAIN_NAME.to_string(),
            input_policy:       RuleAction::Drop,
            output_policy:      RuleAction::Accept,
            default_priority:   0,
            loopback_interface: "lo".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RulesetManager {
    config:  BasicFirewallConfig,
    app:     AppConfig,
    ruleset: schema::Nftables<'static>,
}

impl Default for RulesetManager {
    fn default() -> Self {
        Self::new(BasicFirewallConfig::default())
    }
}

impl RulesetManager {
    pub fn new(config: BasicFirewallConfig) -> Self {
        let mut temp = RulesetManager {
            config,
            app: AppConfig::default(),
            ruleset: schema::Nftables { objects: Vec::<schema::NfObject<'static>>::new().into() },
        };
        if temp.config.enabled {
            temp.ensure_basic_firewall();
        }
        temp
    }

    pub fn from_ruleset(config: BasicFirewallConfig, ruleset: schema::Nftables<'static>) -> Self {
        let mut temp = RulesetManager { config, app: AppConfig::default(), ruleset };
        if temp.config.enabled {
            temp.ensure_basic_firewall();
        }
        temp
    }

    pub fn reset_table(&self) -> Result<()> {
        if !self.kernel_has_table()? {
            return Ok(());
        }
        let mut batch = Batch::new();
        batch.delete(schema::NfListObject::Table(schema::Table {
            family: self.config.family,
            name: Cow::Owned(self.config.table.clone()),
            ..Default::default()
        }));
        match nftables::helper::apply_ruleset(&batch.to_nftables()) {
            Ok(()) => Ok(()),
            Err(e) if e.to_string().contains("No such file or directory") => Ok(()),

            Err(e) => Err(e.into()),
        }
    }

    pub fn apply_only_own_table(&mut self) -> Result<()> {
        if !self.config.enabled {
            bail!("Firewall is disabled; cannot apply ruleset");
        }
        self.reset_table()?;
        self.apply()
    }

    fn add_rule(&mut self, rule: schema::Rule<'static>) {
        if !self.config.enabled {
            println!(
                "Firewall disabled; skipping addition of rule \"{}\"",
                rule.comment.as_deref().unwrap_or("<no comment>")
            );
            return;
        }
        self.objects_mut().push(schema::NfObject::ListObject(schema::NfListObject::Rule(rule)));
    }

    pub fn add_table(&mut self, table: schema::Table<'static>) {
        if !self.config.enabled {
            println!("Firewall disabled; skipping addition of rule \"{}\"", table.name.as_ref());
            return;
        }
        self.objects_mut().push(schema::NfObject::ListObject(schema::NfListObject::Table(table)));
    }

    pub fn add_chain(&mut self, chain: schema::Chain<'static>) {
        if !self.config.enabled {
            println!("Firewall disabled; skipping addition of chain \"{}\"", chain.name.as_ref());
            return;
        }
        self.objects_mut().push(schema::NfObject::ListObject(schema::NfListObject::Chain(chain)));
    }

    pub fn ensure_basic_firewall(&mut self) {
        let config = self.config.clone();
        if !config.enabled {
            return;
        }
        if !self.has_table() {
            self.add_table(build_table_object(config.family, &config.table));
        }

        if !self.has_chain(self.config.input_chain.as_str()) {
            self.add_chain(build_chain_object(
                config.family,
                &config.table,
                &config.input_chain,
                types::NfHook::Input,
                config.default_priority,
                config.input_policy.into(),
            ));
        }

        if !self.has_chain(self.config.output_chain.as_str()) {
            self.add_chain(build_chain_object(
                config.family,
                &config.table,
                &config.output_chain,
                types::NfHook::Output,
                config.default_priority,
                config.output_policy.into(),
            ));
        }

        const LOOPBACK_COMMENT: &str = "allow loopback";
        self.ensure_rule_with_comment(
            LOOPBACK_COMMENT,
            vec![
                build_interface_match(&config.loopback_interface),
                RuleAction::Accept.to_statement(),
            ],
        );

        const ESTABLISHED_COMMENT: &str = "allow established/related";
        self.ensure_rule_with_comment(
            ESTABLISHED_COMMENT,
            vec![
                build_ct_state_match(&["established", "related"]),
                RuleAction::Accept.to_statement(),
            ],
        );

        const INVALID_COMMENT: &str = "drop invalid state";
        self.ensure_rule_with_comment(
            INVALID_COMMENT,
            vec![build_ct_state_match(&["invalid"]), RuleAction::Drop.to_statement()],
        );

        const ICMP_COMMENT: &str = "allow icmp";
        self.ensure_rule_with_comment(
            ICMP_COMMENT,
            vec![build_icmp_match(false), RuleAction::Accept.to_statement()],
        );

        const ICMP6_COMMENT: &str = "allow icmpv6";
        self.ensure_rule_with_comment(
            ICMP6_COMMENT,
            vec![build_icmp_match(true), RuleAction::Accept.to_statement()],
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_simple_rule(
        &mut self,
        proto: Option<&str>,
        src: Option<&str>,
        dst: Option<&str>,
        sport: Option<u16>,
        dport: Option<u16>,
        action: RuleAction,
        comment: &'static str,
    ) -> Result<()> {
        if (sport.is_some() || dport.is_some()) && proto.is_none() {
            bail!("port matches require a protocol");
        }
        let mut statements = build_match_statements(proto, src, dst, sport, dport)?;
        statements.push(action.to_statement());
        self.ensure_rule_with_comment(comment, statements);
        Ok(())
    }

    pub fn add_vxlan_rule(
        &mut self,
        iface: &str,
        action: RuleAction,
        comment: &'static str,
    ) -> Result<()> {
        if !self.config.enabled {
            println!("Firewall disabled; skipping vxlan rule \"{}\"", comment);
            return Ok(());
        }
        let mut statements = vec![build_interface_match(iface)];
        statements.extend(build_match_statements(Some("udp"), None, None, None, Some(4789))?);
        statements.push(action.to_statement());
        self.ensure_rule_with_comment(comment, statements);
        Ok(())
    }

    pub fn remove_rule_by_comment(&mut self, comment: &str) -> bool {
        if !self.config.enabled {
            println!("Firewall disabled; skipping removal of rule \"{}\"", comment);
            return false;
        }
        if let Some(pos) = self.objects_mut().iter().position(|object| match object {
            schema::NfObject::ListObject(schema::NfListObject::Rule(rule)) => {
                rule.comment.as_deref() == Some(comment)
            }
            _ => false,
        }) {
            self.objects_mut().remove(pos);
            true
        } else {
            false
        }
    }

    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.ruleset)?)
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self.to_json_string()?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn from_json_str(config: BasicFirewallConfig, contents: &str) -> Result<Self> {
        let ruleset: schema::Nftables<'static> = serde_json::from_str(contents)?;
        Ok(Self::from_ruleset(config, ruleset))
    }

    pub fn from_json_file(config: BasicFirewallConfig, path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::from_json_str(config, &contents)
    }

    pub fn enable(&mut self, ruleset_file: &Path, config_path: &Path) -> Result<()> {
        if !self.has_table() {
            bail!("Firewall table does not exist; nothing to enable");
        }
        if self.config.enabled {
            bail!("Firewall is already enabled; nothing to do");
        }
        let config = AppConfig::load(config_path)?.get_firewall_config();
        *self = RulesetManager::from_json_file(config, ruleset_file)?;
        self.config.enabled = true;
        let hot_config = self.get_hot_firewall_config();
        self.app.save(config_path, hot_config)?;
        self.apply_only_own_table()?;
        Ok(())
    }
    pub fn disable(&mut self, ruleset_file: &Path, config_path: &Path) -> Result<()> {
        if !self.has_table() {
            bail!("Firewall table does not exist; nothing to disable");
        }
        if !self.config.enabled {
            bail!("Firewall is already disabled; nothing to do");
        }
        self.config.enabled = false;
        let hot_config = self.get_hot_firewall_config();
        self.save_json(ruleset_file)?;
        self.app.save(config_path, hot_config)?;
        self.reset_table()?;
        self.objects_mut().clear();
        Ok(())
    }
    pub fn reload(&mut self, ruleset_file: &Path, config_path: &Path) -> Result<()> {
        if !self.config.enabled {
            bail!("Firewall is disabled; cannot reload");
        }
        self.disable(ruleset_file, config_path)?;
        self.enable(ruleset_file, config_path)?;
        Ok(())
    }
    pub fn get_mode(&self) -> bool {
        self.config.enabled
            && self.has_table()
            && self.has_chain(&self.config.input_chain)
            && !self.objects().is_empty()
    }
    pub fn get_hot_firewall_config(&self) -> BasicFirewallConfig {
        self.config.clone()
    }
    pub fn apply(&mut self) -> Result<()> {
        if !self.config.enabled {
            bail!("Firewall is disabled; cannot apply ruleset");
        }
        nftables::helper::apply_ruleset(&self.ruleset)?;
        Ok(())
    }

    pub fn ruleset(&self) -> &schema::Nftables<'static> {
        &self.ruleset
    }

    pub fn into_ruleset(self) -> schema::Nftables<'static> {
        self.ruleset
    }

    fn objects_mut(&mut self) -> &mut Vec<schema::NfObject<'static>> {
        self.ruleset.objects.to_mut()
    }

    fn objects(&self) -> &[schema::NfObject<'static>] {
        self.ruleset.objects.as_ref()
    }

    fn kernel_has_table(&self) -> Result<bool> {
        let rs = nftables::helper::get_current_ruleset()?;
        Ok(rs.objects.iter().any(|obj| match obj {
            schema::NfObject::ListObject(schema::NfListObject::Table(tbl)) => {
                tbl.family == self.config.family && tbl.name.as_ref() == self.config.table
            }
            _ => false,
        }))
    }
    fn has_table(&self) -> bool {
        self.objects().iter().any(|object| match object {
            schema::NfObject::ListObject(schema::NfListObject::Table(tbl)) => {
                tbl.family == self.config.family && tbl.name.as_ref() == self.config.table
            }
            _ => false,
        })
    }

    fn has_chain(&self, name: &str) -> bool {
        self.objects().iter().any(|object| match object {
            schema::NfObject::ListObject(schema::NfListObject::Chain(ch)) => {
                ch.family == self.config.family
                    && ch.table.as_ref() == self.config.table
                    && ch.name.as_ref() == name
            }
            _ => false,
        })
    }

    fn rule_with_comment_exists(&self, comment: &str) -> bool {
        self.objects().iter().any(|object| match object {
            schema::NfObject::ListObject(schema::NfListObject::Rule(rule)) => {
                rule.comment.as_deref() == Some(comment)
            }
            _ => false,
        })
    }

    pub fn ensure_rule_with_comment(
        &mut self,
        comment: &'static str,
        statements: Vec<Statement<'static>>,
    ) {
        let config = self.config.clone();
        if !config.enabled {
            println!("Firewall disabled; skipping rule \"{}\"", comment);
            return;
        }
        if self.rule_with_comment_exists(comment) {
            return;
        }
        let rule = build_rule(
            config.family,
            &config.table,
            &config.input_chain,
            statements,
            Some(comment),
        );
        self.add_rule(rule);
    }
}

impl RuleAction {
    fn to_statement(self) -> Statement<'static> {
        match self {
            RuleAction::Accept => Statement::Accept(Some(Accept {})),
            RuleAction::Drop => Statement::Drop(Some(Drop {})),
        }
    }
}

fn build_rule(
    family: types::NfFamily,
    table: &str,
    chain: &str,
    expr: Vec<Statement<'static>>,
    comment: Option<&str>,
) -> schema::Rule<'static> {
    schema::Rule {
        family,
        table: Cow::Owned(table.to_string()),
        chain: Cow::Owned(chain.to_string()),
        expr: expr.into(),
        comment: comment.map(|c| Cow::Owned(c.to_string())),
        ..Default::default()
    }
}

fn build_match_statements(
    proto: Option<&str>,
    src: Option<&str>,
    dst: Option<&str>,
    sport: Option<u16>,
    dport: Option<u16>,
) -> Result<Vec<Statement<'static>>> {
    let mut statements = Vec::new();
    if let Some(proto) = proto {
        statements.push(build_proto_match(proto));
    }
    if let Some(src) = src {
        statements.push(build_address_statement("saddr", src));
    }
    if let Some(dst) = dst {
        statements.push(build_address_statement("daddr", dst));
    }
    if let Some(port) = sport {
        let proto = proto.expect("protocol required for sport");
        statements.push(build_port_statement("sport", port, proto));
    }
    if let Some(port) = dport {
        let proto = proto.expect("protocol required for dport");
        statements.push(build_port_statement("dport", port, proto));
    }
    Ok(statements)
}

fn build_ct_state_match(states: &[&str]) -> Statement<'static> {
    let right = if states.len() == 1 {
        Expression::String(Cow::Owned(states[0].to_string()))
    } else {
        let values = states
            .iter()
            .map(|state| Expression::String(Cow::Owned((*state).to_string())))
            .collect();
        Expression::List(values)
    };
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::CT(CT {
            key:    Cow::Borrowed("state"),
            family: None,
            dir:    None,
        })),
        right,
        op: Operator::IN,
    })
}

fn build_table_object(family: types::NfFamily, table: &str) -> schema::Table<'static> {
    schema::Table { family, name: Cow::Owned(table.to_string()), ..Default::default() }
}

fn build_chain_object(
    family: types::NfFamily,
    table: &str,
    name: &str,
    hook: types::NfHook,
    priority: i32,
    policy: types::NfChainPolicy,
) -> schema::Chain<'static> {
    schema::Chain {
        family,
        table: Cow::Owned(table.to_string()),
        name: Cow::Owned(name.to_string()),
        _type: Some(types::NfChainType::Filter),
        hook: Some(hook),
        prio: Some(priority),
        policy: Some(policy),
        ..Default::default()
    }
}

fn build_proto_match(proto: &str) -> Statement<'static> {
    Statement::Match(Match {
        left:  Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::L4proto })),
        right: Expression::String(Cow::Owned(proto.to_ascii_lowercase())),
        op:    Operator::EQ,
    })
}

fn build_address_statement(field: &'static str, value: &str) -> Statement<'static> {
    let protocol = if value.contains(':') { Cow::Borrowed("ip6") } else { Cow::Borrowed("ip") };
    let expr = if let Some((addr, prefix_len)) = split_prefix(value) {
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::Owned(addr))),
            len:  prefix_len,
        }))
    } else {
        Expression::String(Cow::Owned(value.to_string()))
    };
    build_payload_match(protocol, field, expr)
}

fn build_port_statement(field: &'static str, port: u16, proto: &str) -> Statement<'static> {
    let protocol = Cow::Owned(proto.to_ascii_lowercase());
    build_payload_match(protocol, field, Expression::Number(port as u32))
}

fn build_icmp_match(is_ipv6: bool) -> Statement<'static> {
    if is_ipv6 {
        build_payload_match(
            Cow::Borrowed("ip6"),
            "nexthdr",
            Expression::String(Cow::Borrowed("icmpv6")),
        )
    } else {
        build_payload_match(
            Cow::Borrowed("ip"),
            "protocol",
            Expression::String(Cow::Borrowed("icmp")),
        )
    }
}

fn build_payload_match(
    protocol: Cow<'static, str>,
    field: &'static str,
    right: Expression<'static>,
) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
            protocol,
            field: Cow::Borrowed(field),
        }))),
        right,
        op: Operator::EQ,
    })
}

fn build_interface_match(iface: &str) -> Statement<'static> {
    Statement::Match(Match {
        left:  Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
        right: Expression::String(Cow::Owned(iface.to_string())),
        op:    Operator::EQ,
    })
}

fn split_prefix(value: &str) -> Option<(String, u32)> {
    let mut iter = value.split('/');
    let addr = iter.next()?.to_string();
    let mask = iter.next()?;
    let len = mask.parse().ok()?;
    Some((addr, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_rule<'a>(manager: &'a RulesetManager, comment: &str) -> &'a schema::Rule<'static> {
        manager
            .ruleset()
            .objects
            .iter()
            .find_map(|object| match object {
                schema::NfObject::ListObject(schema::NfListObject::Rule(rule))
                    if rule.comment.as_deref() == Some(comment) =>
                {
                    Some(rule)
                }
                _ => None,
            })
            .expect("rule not found")
    }

    #[test]
    fn add_simple_rule_builds_matches() {
        let mut manager = RulesetManager::new(BasicFirewallConfig::default());
        manager
            .add_simple_rule(
                Some("tcp"),
                Some("10.0.0.0/24"),
                None,
                None,
                Some(22),
                RuleAction::Accept,
                "allow ssh",
            )
            .unwrap();

        let rule = find_rule(&manager, "allow ssh");
        assert_eq!(rule.chain.as_ref(), DEFAULT_INPUT_CHAIN_NAME);
        assert!(rule
            .expr
            .iter()
            .any(|stmt| matches!(stmt, Statement::Match(Match { left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { field, .. }))), right: Expression::Number(val), .. }) if field.as_ref() == "dport" && *val == 22)));
    }

    #[test]
    fn ensure_basic_firewall_builds_table_chains_and_loopback_rule() {
        let mut manager = RulesetManager::new(BasicFirewallConfig::default());
        manager.ensure_basic_firewall();

        assert!(manager.ruleset().objects.iter().any(|object| matches!(object,
            schema::NfObject::ListObject(schema::NfListObject::Table(table)) if table.name.as_ref() == "chm_table")));

        assert!(manager.ruleset().objects.iter().any(|object| matches!(object,
            schema::NfObject::ListObject(schema::NfListObject::Chain(chain)) if chain.name.as_ref() == "chm_output" && chain.policy == Some(types::NfChainPolicy::Accept))));

        assert!(manager.ruleset().objects.iter().any(|object| matches!(object,
            schema::NfObject::ListObject(schema::NfListObject::Rule(rule)) if rule.comment.as_deref() == Some("allow loopback"))));

        let established = find_rule(&manager, "allow established/related");
        assert!(established.expr.iter().any(|stmt| matches!(
            stmt,
            Statement::Match(Match { left: Expression::Named(NamedExpression::CT(_)), .. })
        )));

        let invalid = find_rule(&manager, "drop invalid state");
        assert!(matches!(invalid.expr.last(), Some(Statement::Drop(_))));

        let icmp = find_rule(&manager, "allow icmp");
        assert!(icmp.expr.iter().any(|stmt| matches!(stmt,
            Statement::Match(Match { left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { field, .. }))), .. }) if field.as_ref() == "protocol")));

        let icmp6 = find_rule(&manager, "allow icmpv6");
        assert!(icmp6.expr.iter().any(|stmt| matches!(stmt,
            Statement::Match(Match { left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { field, .. }))), .. }) if field.as_ref() == "nexthdr")));
    }

    #[test]
    fn add_vxlan_rule_includes_interface_and_port() {
        let mut manager = RulesetManager::new(BasicFirewallConfig::default());
        manager.add_vxlan_rule("vxlan0", RuleAction::Accept, "vxlan").unwrap();

        let rule = find_rule(&manager, "vxlan");
        assert!(rule.expr.iter().any(|stmt| matches!(stmt,
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
                right: Expression::String(value),
                ..
            }) if value.as_ref() == "vxlan0")));
        assert!(rule
            .expr
            .iter()
            .any(|stmt| matches!(stmt,
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { field, .. }))),
                    right: Expression::Number(val),
                    ..
                }) if field.as_ref() == "dport" && *val == 4789)));
    }

    #[test]
    fn remove_rule_by_comment_works() {
        let mut manager = RulesetManager::new(BasicFirewallConfig::default());
        manager
            .add_simple_rule(Some("tcp"), None, None, None, Some(80), RuleAction::Accept, "http")
            .unwrap();
        assert!(manager.remove_rule_by_comment("http"));
        assert!(!manager.remove_rule_by_comment("http"));
    }

    #[test]
    fn json_roundtrip_preserves_rules() {
        let mut manager = RulesetManager::new(BasicFirewallConfig::default());
        manager
            .add_simple_rule(Some("icmp"), None, None, None, None, RuleAction::Accept, "icmp")
            .unwrap();

        let json = manager.to_json_string().unwrap();
        let restored =
            RulesetManager::from_json_str(BasicFirewallConfig::default(), &json).unwrap();
        find_rule(&restored, "icmp");
    }

    #[test]
    fn drop_action_is_supported() {
        let mut manager = RulesetManager::new(BasicFirewallConfig::default());
        manager
            .add_simple_rule(Some("udp"), None, None, None, Some(53), RuleAction::Drop, "block dns")
            .unwrap();
        let rule = find_rule(&manager, "block dns");
        assert!(matches!(rule.expr.last(), Some(Statement::Drop(_))));
    }
}
