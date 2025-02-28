use serde_json::Value;
use std::env;

pub(crate) fn get_env<T: std::str::FromStr + ToString>(key: &str, default: T) -> T {
    env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .unwrap_or(default)
}

pub(crate) fn get_json_array(key: &str) -> Vec<String> {
    env::var(key)
        .map(|v| serde_json::from_str::<Value>(&v).unwrap_or(Value::Array(vec![])))
        .map(|v| {
            v.as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|i| i.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
