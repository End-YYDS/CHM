use api_server::AllSchemas;
use schemars::schema_for;
use std::{fs, path::Path};

fn main() {
    let root_schema = schema_for!(AllSchemas);
    let json = serde_json::to_string_pretty(&root_schema).unwrap();
    let out_dir = Path::new("schema");
    fs::create_dir_all(out_dir).unwrap();
    let out_path = out_dir.join("all.schema.json");
    fs::write(&out_path, json).unwrap();
    println!("All-in-one schema written to {}", out_path.display());
}
